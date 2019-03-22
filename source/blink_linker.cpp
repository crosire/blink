/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "blink.hpp"
#include "coff_reader.hpp"
#include "scoped_handle.hpp"
#include <assert.h>
#include <Windows.h>
#include <TlHelp32.h>

static void write_jump(uint8_t *address, const uint8_t *jump_target)
{
#ifdef _M_IX86
	DWORD protect = PAGE_READWRITE;
	VirtualProtect(address, 5, protect, &protect);

	// JMP
	address[0] = 0xE9;
	*reinterpret_cast<int32_t *>(address + 1) = jump_target - (address + 5);

	VirtualProtect(address, 5, protect, &protect);
#endif
#ifdef _M_AMD64
	DWORD protect = PAGE_READWRITE;
	VirtualProtect(address, 12, protect, &protect);

	// MOV RAX, [target_address]
	// JMP RAX
	address[0] = 0x48;
	address[1] = 0xB8;
	*reinterpret_cast<uint64_t *>(address + 2) = reinterpret_cast<uintptr_t>(jump_target);
	address[10] = 0xFF;
	address[11] = 0xE0;

	VirtualProtect(address, 12, protect, &protect);
#endif
}

static uint8_t *find_free_memory_region(uint8_t *address, size_t size)
{
#ifdef _M_AMD64
	SYSTEM_INFO sysinfo;
	MEMORY_BASIC_INFORMATION meminfo;
	GetSystemInfo(&sysinfo);

	address -= reinterpret_cast<uintptr_t>(address) % sysinfo.dwAllocationGranularity;
	address += sysinfo.dwAllocationGranularity;
	auto maxaddress = static_cast<uint8_t *>(sysinfo.lpMaximumApplicationAddress);
	maxaddress -= size;

	while (address < maxaddress)
	{
		if (VirtualQuery(address, &meminfo, sizeof(meminfo)) == 0)
			break;

		if (meminfo.State == MEM_FREE)
			return address;

		address = static_cast<uint8_t *>(meminfo.BaseAddress) + meminfo.RegionSize;

		// Round up to the next allocation granularity
		address += sysinfo.dwAllocationGranularity - 1;
		address -= reinterpret_cast<uintptr_t>(address) % sysinfo.dwAllocationGranularity;
	}
#endif
	return nullptr;
}

struct thread_scope_guard : scoped_handle
{
	thread_scope_guard() :
		scoped_handle(CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0))
	{
		if (handle == INVALID_HANDLE_VALUE)
			return;

		THREADENTRY32 te = { sizeof(te) };

		if (Thread32First(handle, &te) && te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32ThreadID) + sizeof(te.th32ThreadID))
		{
			do
			{
				if (te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId())
					continue; // Do not suspend the current thread (which belongs to blink)

				const scoped_handle thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);

				if (thread == nullptr)
					continue;

				SuspendThread(thread);
			}
			while (Thread32Next(handle, &te));
		}
	}
	~thread_scope_guard()
	{
		if (handle == INVALID_HANDLE_VALUE)
			return;

		THREADENTRY32 te = { sizeof(te) };

		if (Thread32First(handle, &te) && te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32ThreadID) + sizeof(te.th32ThreadID))
		{
			do
			{
				if (te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId())
					continue;

				const scoped_handle thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);

				if (thread == nullptr)
					continue;

				ResumeThread(thread);
			}
			while (Thread32Next(handle, &te));
		}
	}
};

bool blink::application::link(const std::filesystem::path &path)
{
	// Object file can be a normal COFF or an extended COFF
	COFF_HEADER header;
	const scoped_handle file = open_coff_file(path, header);
	if (file == INVALID_HANDLE_VALUE)
		return false;

	return !header.is_extended() ?
		link<IMAGE_SYMBOL>(file, header.obj) :
		link<IMAGE_SYMBOL_EX>(file, header.bigobj);
}

template <typename SYMBOL_TYPE, typename HEADER_TYPE>
bool blink::application::link(HANDLE file, const HEADER_TYPE &header)
{
	thread_scope_guard _scope_guard_; // Make sure the application doesn't access any of the code pages while they are being modified

#ifdef _M_IX86
	if (header.Machine != IMAGE_FILE_MACHINE_I386)
#endif
#ifdef _M_AMD64
	if (header.Machine != IMAGE_FILE_MACHINE_AMD64)
#endif
	{
		print("Input file is not of a valid format or was compiled for a different processor architecture.");
		return false;
	}

	// Read section headers from input file (there is no optional header in COFF files, so it is right after the header read above)
	std::vector<IMAGE_SECTION_HEADER> sections(header.NumberOfSections);
	if (DWORD read; !ReadFile(file, sections.data(), header.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), &read, nullptr))
	{
		print("Failed to read an image file sections.");
		return false;
	}

	// Read symbol table from input file
	SetFilePointer(file, header.PointerToSymbolTable, nullptr, FILE_BEGIN);

	std::vector<SYMBOL_TYPE> symbols(header.NumberOfSymbols);
	if (DWORD read; !ReadFile(file, symbols.data(), header.NumberOfSymbols * sizeof(SYMBOL_TYPE), &read, nullptr))
	{
		print("Failed to read an image file symbols.");
		return false;
	}

	// The string table follows after the symbol table and is usually at the end of the file
	const DWORD string_table_size = GetFileSize(file, nullptr) - (header.PointerToSymbolTable + header.NumberOfSymbols * sizeof(SYMBOL_TYPE));

	std::vector<char> strings(string_table_size);
	if (DWORD read; !ReadFile(file, strings.data(), string_table_size, &read, nullptr))
	{
		print("Failed to read a string table.");
		return false;
	}

	// Calculate total module size
	SIZE_T allocated_module_size = 0;

	for (const IMAGE_SECTION_HEADER &section : sections)
	{
		// Add space for section data and potential alignment
		allocated_module_size += 256 + section.SizeOfRawData + section.NumberOfRelocations * sizeof(IMAGE_RELOCATION);

#ifdef _M_AMD64
		// Add space for relay thunk
		if (section.Characteristics & IMAGE_SCN_CNT_CODE)
			allocated_module_size += section.NumberOfRelocations * 12;
#endif
	}

	// Allocate executable memory region close to the executable image base (this is done so that relative jumps like 'IMAGE_REL_AMD64_REL32' fit into the required 32-bit).
	// Successfully loaded object files are never deallocated again to avoid corrupting the function rerouting generated below. The virtual memory is freed at process exit by Windows.
	const auto module_base = static_cast<BYTE *>(VirtualAlloc(find_free_memory_region(_image_base, allocated_module_size), allocated_module_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

	if (module_base == nullptr)
	{
		print("Failed to allocate executable memory region.");
		return false;
	}

	// Initialize sections
	auto section_base = module_base;

	for (IMAGE_SECTION_HEADER &section : sections)
	{
		// Skip over all sections that do not need linking
		if (section.Characteristics & (IMAGE_SCN_LNK_INFO | IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_MEM_DISCARDABLE))
		{
			section.NumberOfRelocations = 0; // Ensure that these are not handled by relocation below
			continue;
		}

		// Check section alignment
		UINT_PTR alignment = section.Characteristics & IMAGE_SCN_ALIGN_MASK;
		alignment = alignment ? 1 << ((alignment >> 20) - 1) : 1;

		// Align section memory base pointer to its required alignment
		section_base = reinterpret_cast<BYTE *>((reinterpret_cast<UINT_PTR>(section_base) + (alignment - 1)) & ~(alignment - 1));

		// Uninitialized sections do not have any data attached and they were already zeroed by 'VirtualAlloc', so skip them here
		if (section.PointerToRawData != 0)
		{
			SetFilePointer(file, section.PointerToRawData, nullptr, FILE_BEGIN);

			if (DWORD read; !ReadFile(file, section_base, section.SizeOfRawData, &read, nullptr))
			{
				print("Failed to read a section raw data.");
				return false;
			}
		}

		section.PointerToRawData = static_cast<DWORD>(section_base - module_base);
		section_base += section.SizeOfRawData;

		// Read any relocation data attached to this section
		if (section.PointerToRelocations != 0)
		{
			SetFilePointer(file, section.PointerToRelocations, nullptr, FILE_BEGIN);

			if (DWORD read; !ReadFile(file, section_base, section.NumberOfRelocations * sizeof(IMAGE_RELOCATION), &read, nullptr))
			{
				print("Failed to read relocations.");
				return false;
			}
		}

		section.PointerToRelocations = static_cast<DWORD>(section_base - module_base);
		section_base += section.NumberOfRelocations * sizeof(IMAGE_RELOCATION);

#if 0
		// Protect section memory with requested protection flags
		DWORD protect = PAGE_NOACCESS;

		switch (section.Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE))
		{
		case IMAGE_SCN_MEM_READ:
			protect = PAGE_READONLY;
			break;
		case IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
			protect = PAGE_READWRITE;
			break;
		case IMAGE_SCN_MEM_EXECUTE:
			protect = PAGE_EXECUTE;
			break;
		case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ:
			protect = PAGE_EXECUTE_READ;
			break;
		case IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE:
			protect = PAGE_EXECUTE_READWRITE;
			break;
		}

		if (section.Characteristics & IMAGE_SCN_MEM_NOT_CACHED)
			protect |= PAGE_NOCACHE;

		if (!VirtualProtect(module_base + section.PointerToRawData, section.SizeOfRawData, protect, &protect))
			print("Failed to protect section '" + std::string(reinterpret_cast<const char(&)[]>(section.Name)) + "'.");
#endif
	}

	// Resolve internal and external symbols
	std::vector<BYTE *> local_symbol_addresses(header.NumberOfSymbols);
	std::vector<std::pair<BYTE *, const BYTE *>> image_function_relocations;

	for (DWORD i = 0; i < header.NumberOfSymbols; i++)
	{
		BYTE *target_address = nullptr;
		const SYMBOL_TYPE &symbol = symbols[i];

		// Get symbol name from string table if it is a long name
		std::string symbol_name;
		if (symbol.N.Name.Short == 0)
		{
			assert(symbol.N.Name.Long < string_table_size);

			symbol_name = strings.data() + symbol.N.Name.Long;
		}
		else
		{
			const auto short_name = reinterpret_cast<const char *>(symbol.N.ShortName);

			symbol_name = std::string(short_name, strnlen(short_name, IMAGE_SIZEOF_SHORT_NAME));
		}

		const auto symbol_table_lookup = _symbols.find(symbol_name);

		if (symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber == IMAGE_SYM_UNDEFINED)
		{
			if (symbol_table_lookup == _symbols.end())
			{
				VirtualFree(module_base, 0, MEM_RELEASE);

				print("Unresolved external symbol '" + symbol_name + "'.");
				return false;
			}

			target_address = static_cast<BYTE *>(symbol_table_lookup->second);
		}
		else if (symbol.StorageClass == IMAGE_SYM_CLASS_WEAK_EXTERNAL)
		{
			if (symbol_table_lookup != _symbols.end())
			{
				target_address = static_cast<BYTE *>(symbol_table_lookup->second);
			}
			else if (symbol.NumberOfAuxSymbols != 0)
			{
				const auto aux_symbol = reinterpret_cast<const IMAGE_AUX_SYMBOL_EX &>(symbols[i + 1]).Sym;

				assert(aux_symbol.WeakDefaultSymIndex < i && "Unexpected symbol ordering for weak external symbol.");

				target_address = local_symbol_addresses[aux_symbol.WeakDefaultSymIndex];
			}
			else
			{
				VirtualFree(module_base, 0, MEM_RELEASE);

				print("Unresolved weak external symbol '" + symbol_name + "'.");
				return false;
			}
		}
		else if (symbol.SectionNumber > IMAGE_SYM_UNDEFINED)
		{
			const IMAGE_SECTION_HEADER &section = sections[symbol.SectionNumber - 1];
			target_address = module_base + section.PointerToRawData + symbol.Value;

			if (symbol_table_lookup != _symbols.end() && symbol_name != reinterpret_cast<const char(&)[]>(section.Name))
			{
				const auto old_address = static_cast<BYTE *>(symbol_table_lookup->second);

				if (ISFCN(symbol.Type))
				{
					image_function_relocations.push_back({ old_address, target_address });
				}
				else if (strcmp(reinterpret_cast<const char *>(section.Name), ".bss") == 0 || strcmp(reinterpret_cast<const char *>(section.Name), ".data") == 0)
				{
					// Continue to use existing data from previous uninitialized (.bss) and initialized (.data) sections instead of replacing it
					target_address = old_address;
				}
			}
		}

		_symbols[symbol_name] = local_symbol_addresses[i] = target_address;

		i += symbol.NumberOfAuxSymbols;
	}

	// Perform relocation on each section
	for (const IMAGE_SECTION_HEADER &section : sections)
	{
		const auto section_relocation_table = reinterpret_cast<const IMAGE_RELOCATION *>(module_base + section.PointerToRelocations);

		for (unsigned int k = 0; k < section.NumberOfRelocations; ++k)
		{
			const IMAGE_RELOCATION &relocation = section_relocation_table[k];
			const auto relocation_address = module_base + section.PointerToRawData + section.VirtualAddress + relocation.VirtualAddress;
			auto target_address = local_symbol_addresses[relocation.SymbolTableIndex];

#ifdef _M_AMD64
			// Add relay thunk if distance to target exceeds 32-bit range
			if (target_address - relocation_address > 0xFFFFFFFF && ISFCN(symbols[relocation.SymbolTableIndex].Type))
			{
				write_jump(section_base, target_address);

				target_address = section_base;
				section_base += 12;
			}
#endif
			switch (relocation.Type)
			{
#ifdef _M_IX86
			// No relocation necessary
			case IMAGE_REL_I386_ABSOLUTE:
				break;
			// Absolute virtual address
			case IMAGE_REL_I386_DIR32:
				*reinterpret_cast<uint32_t *>(relocation_address) = reinterpret_cast<uintptr_t>(target_address);
				break;
			// Relative virtual address to __ImageBase
			case IMAGE_REL_I386_DIR32NB:
				*reinterpret_cast< int32_t *>(relocation_address) = target_address - _image_base;
				break;
			// Relative to next instruction after relocation
			case IMAGE_REL_I386_REL32:
				*reinterpret_cast< int32_t *>(relocation_address) = target_address - (relocation_address + 4);
				break;
			case IMAGE_REL_I386_SECREL:
				*reinterpret_cast<uint32_t *>(relocation_address) = reinterpret_cast<uintptr_t>(target_address) & 0xFFF; // TODO: This was found by comparing generated ASM, probably not correct
				break;
#endif
#ifdef _M_AMD64
			// Absolute virtual 64-bit address
			case IMAGE_REL_AMD64_ADDR64:
				*reinterpret_cast<uint64_t *>(relocation_address) = reinterpret_cast<uintptr_t>(target_address);
				break;
			// Absolute virtual 32-bit address
			case IMAGE_REL_AMD64_ADDR32:
				assert(reinterpret_cast<uint64_t>(target_address) >> 32 == 0 && "Address overflow in absolute relocation.");
				*reinterpret_cast<uint32_t *>(relocation_address) = reinterpret_cast<uintptr_t>(target_address) & 0xFFFFFFFF;
				break;
			// Relative virtual address to __ImageBase
			case IMAGE_REL_AMD64_ADDR32NB:
				assert(target_address - _image_base == static_cast<int32_t>(target_address - _image_base) && "Address overflow in relative relocation.");
				*reinterpret_cast< int32_t *>(relocation_address) = static_cast<int32_t>(target_address - _image_base);
				break;
			// Relative virtual address to next instruction after relocation
			case IMAGE_REL_AMD64_REL32:
			case IMAGE_REL_AMD64_REL32_1:
			case IMAGE_REL_AMD64_REL32_2:
			case IMAGE_REL_AMD64_REL32_3:
			case IMAGE_REL_AMD64_REL32_4:
			case IMAGE_REL_AMD64_REL32_5:
				assert(target_address - relocation_address == static_cast<int32_t>(target_address - relocation_address) && "Address overflow in relative relocation.");
				*reinterpret_cast< int32_t *>(relocation_address) = static_cast<int32_t>(target_address - (relocation_address + 4 + (relocation.Type - IMAGE_REL_AMD64_REL32)));
				break;
			case IMAGE_REL_AMD64_SECREL:
				*reinterpret_cast<uint32_t *>(relocation_address) = reinterpret_cast<uintptr_t>(target_address) & 0xFFF; // TODO: This was found by comparing generated ASM, probably not correct
				break;
#endif
			default:
				print("Unimplemented relocation type '" + std::to_string(relocation.Type) + "'.");
				break;
			}
		}
	}

	// Reroute old functions to new code
	for (const auto &relocation : image_function_relocations)
		write_jump(relocation.first, relocation.second);

	FlushInstructionCache(GetCurrentProcess(), module_base, allocated_module_size);

	print("Successfully linked object file into executable image.");

	return true;
}
