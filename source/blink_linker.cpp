#include "blink.hpp"
#include <assert.h>
#include <vector>
#include <fstream>
#include <algorithm>
#include <Windows.h>
#include <TlHelp32.h>

namespace blink
{
	namespace
	{
		void write_jump(uint8_t *address, const uint8_t *jump_target)
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
		void *find_free_memory_region(uint8_t *address, size_t size)
		{
#ifdef _M_AMD64
			uint8_t *maxaddress;
			SYSTEM_INFO sysinfo;
			MEMORY_BASIC_INFORMATION meminfo;

			GetSystemInfo(&sysinfo);

			address -= reinterpret_cast<uintptr_t>(address) % sysinfo.dwAllocationGranularity;
			address += sysinfo.dwAllocationGranularity;
			maxaddress = static_cast<uint8_t *>(sysinfo.lpMaximumApplicationAddress);
			maxaddress -= size;

			while (address < maxaddress)
			{
				if (VirtualQuery(address, &meminfo, sizeof(MEMORY_BASIC_INFORMATION)) == 0)
				{
					break;
				}

				if (meminfo.State == MEM_FREE)
				{
					return address;
				}

				address = static_cast<uint8_t *>(meminfo.BaseAddress) + meminfo.RegionSize;

				// Round up to the next allocation granularity
				address += sysinfo.dwAllocationGranularity - 1;
				address -= reinterpret_cast<uintptr_t>(address) % sysinfo.dwAllocationGranularity;
			}
#endif
			return nullptr;
		}
		size_t additional_data_size(HANDLE file)
		{
			IMAGE_FILE_HEADER header;
			DWORD read = 0, size = sizeof(header);

			if (!ReadFile(file, &header, size, &read, nullptr) || read != size)
			{
				SetFilePointer(file, 0, nullptr, FILE_BEGIN);
				return 0;
			}

			SetFilePointer(file, header.SizeOfOptionalHeader, nullptr, FILE_CURRENT);

			size = header.NumberOfSections * sizeof(IMAGE_SECTION_HEADER);
			const auto sections = static_cast<IMAGE_SECTION_HEADER *>(alloca(size));

			if (!ReadFile(file, sections, size, &read, nullptr) || read != size)
			{
				SetFilePointer(file, 0, nullptr, FILE_BEGIN);
				return 0;
			}

			SetFilePointer(file, 0, nullptr, FILE_BEGIN);

			size = 0;

			for (unsigned int i = 0; i < header.NumberOfSections; i++)
			{
				if (sections[i].PointerToRawData == 0 && sections[i].Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
				{
					size += sections[i].SizeOfRawData;
				}
#ifdef _M_AMD64
				else if (sections[i].Characteristics & IMAGE_SCN_CNT_CODE)
				{
					size += sections[i].NumberOfRelocations * 12;
				}
#endif
			}

			return size;
		}

		void resume_all_threads()
		{
			const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

			if (snapshot == INVALID_HANDLE_VALUE)
			{
				return;
			}

			THREADENTRY32 te = { sizeof(te) };

			if (Thread32First(snapshot, &te) && te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32ThreadID) + sizeof(te.th32ThreadID))
			{
				do
				{
					if (te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId())
					{
						continue;
					}

					const auto thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);

					if (thread == nullptr)
					{
						continue;
					}

					ResumeThread(thread);
					CloseHandle(thread);
				}
				while (Thread32Next(snapshot, &te));
			}

			CloseHandle(snapshot);
		}
		void suspend_all_threads()
		{
			const auto snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

			if (snapshot == INVALID_HANDLE_VALUE)
			{
				return;
			}

			THREADENTRY32 te = { sizeof(te) };

			if (Thread32First(snapshot, &te) && te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32ThreadID) + sizeof(te.th32ThreadID))
			{
				do
				{
					if (te.th32OwnerProcessID != GetCurrentProcessId() || te.th32ThreadID == GetCurrentThreadId())
					{
						continue;
					}

					const auto thread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);

					if (thread == nullptr)
					{
						continue;
					}

					SuspendThread(thread);
					CloseHandle(thread);
				}
				while (Thread32Next(snapshot, &te));
			}

			CloseHandle(snapshot);
		}
	}

	bool application::link(const std::string &path)
	{
		struct scope_guard
		{
			scope_guard() { suspend_all_threads(); }
			~scope_guard() { resume_all_threads(); }
		} _scope_guard_;

		const HANDLE file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (file == INVALID_HANDLE_VALUE)
		{
			print("JETLINK: Failed to open input file.\n");

			return false;
		}

		DWORD modulesize = GetFileSize(file, nullptr), modulesize_read = 0;
		const size_t allocsize = modulesize + additional_data_size(file);

		// Allocate executable memory region close to the executable image base.
		// Successfully loaded object files are never deallocated again to avoid corrupting the function rerouting generated below.
		// The virtual memory is freed at process exit by Windows.
		const auto modulebase = static_cast<uint8_t *>(VirtualAlloc(find_free_memory_region(_imagebase, allocsize), allocsize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));

		if (modulebase == nullptr)
		{
			CloseHandle(file);

			print("JETLINK: Failed to allocate executable memory region.\n");

			return false;
		}

		// Read object file into memory region
		ReadFile(file, modulebase, modulesize, &modulesize_read, nullptr);
		CloseHandle(file);

		if (modulesize_read < modulesize)
		{
			VirtualFree(modulebase, modulesize, MEM_RELEASE);

			print("JETLINK: Failed to read data from input file.\n");

			return false;
		}

		const auto &moduleheader = *reinterpret_cast<const IMAGE_FILE_HEADER *>(modulebase);

#ifdef _M_IX86
		if (moduleheader.Machine != IMAGE_FILE_MACHINE_I386)
#endif
#ifdef _M_AMD64
		if (moduleheader.Machine != IMAGE_FILE_MACHINE_AMD64)
#endif
		{
			VirtualFree(modulebase, modulesize, MEM_RELEASE);

			print("JETLINK: Input file is not of a valid format or was compiled for a different processor architecture.\n");

			return false;
		}

		auto additional_data_base = modulebase + modulesize;
		const auto symbol_table_base = reinterpret_cast<const IMAGE_SYMBOL *>(modulebase + moduleheader.PointerToSymbolTable);
		const auto section_header_base = reinterpret_cast<IMAGE_SECTION_HEADER *>(modulebase + sizeof(IMAGE_FILE_HEADER) + moduleheader.SizeOfOptionalHeader);
		std::vector<uint8_t *> local_symbol_addresses(moduleheader.NumberOfSymbols);
		std::vector<std::pair<uint8_t *, const uint8_t *>> image_function_relocations;

		// Allocate uninitialized data sections
		for (unsigned int i = 0; i < moduleheader.NumberOfSections; i++)
		{
			IMAGE_SECTION_HEADER &section = section_header_base[i];

			if (section.PointerToRawData == 0 && section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			{
				assert(additional_data_base + section.SizeOfRawData <= modulebase + allocsize && "JETLINK: Additional data allocated is not big enough.");

				// Memory was already initialized to zero by VirtualAlloc
				section.PointerToRawData = static_cast<DWORD>(additional_data_base - modulebase);

				additional_data_base += section.SizeOfRawData;
			}
		}

		// Resolve internal and external symbols
		for (unsigned int i = 0; i < moduleheader.NumberOfSymbols; i++)
		{
			uint8_t *target_address = nullptr;
			const IMAGE_SYMBOL &symbol = symbol_table_base[i];
			const auto symbol_name = symbol.N.Name.Short == 0 ? std::string(reinterpret_cast<const char *>(symbol_table_base + moduleheader.NumberOfSymbols) + symbol.N.Name.Long) : std::string(reinterpret_cast<const char *>(symbol.N.ShortName), strnlen(reinterpret_cast<const char *>(symbol.N.ShortName), IMAGE_SIZEOF_SHORT_NAME));
			const auto symbol_table_lookup = _symbols.find(symbol_name);

			if (symbol.StorageClass == IMAGE_SYM_CLASS_EXTERNAL && symbol.SectionNumber == IMAGE_SYM_UNDEFINED)
			{
				if (symbol_table_lookup == _symbols.end())
				{
					VirtualFree(modulebase, modulesize, MEM_RELEASE);

					print("JETLINK: Unresolved external symbol '" + symbol_name + "'.\n");

					return false;
				}

				target_address = static_cast<uint8_t *>(symbol_table_lookup->second);
			}
			else if (symbol.StorageClass == IMAGE_SYM_CLASS_WEAK_EXTERNAL)
			{
				if (symbol_table_lookup != _symbols.end())
				{
					target_address = static_cast<uint8_t *>(symbol_table_lookup->second);
				}
				else if (symbol.NumberOfAuxSymbols != 0)
				{
					const auto auxsymbol = reinterpret_cast<const IMAGE_AUX_SYMBOL_EX &>(symbol_table_base[i + 1]).Sym;

					assert(auxsymbol.WeakDefaultSymIndex < i && "JETLINK: Unexpected symbol ordering for weak external symbol.");

					target_address = local_symbol_addresses[auxsymbol.WeakDefaultSymIndex];
				}
				else
				{
					VirtualFree(modulebase, modulesize, MEM_RELEASE);

					print("JETLINK: Unresolved weak external symbol '" + symbol_name + "'.\n");

					return false;
				}
			}
			else if (symbol.SectionNumber > IMAGE_SYM_UNDEFINED)
			{
				const IMAGE_SECTION_HEADER &section = section_header_base[symbol.SectionNumber - 1];
				target_address = modulebase + section.PointerToRawData + symbol.Value;

				if (symbol_table_lookup != _symbols.end() && symbol_name != reinterpret_cast<const char(&)[]>(section.Name))
				{
					const auto old_address = static_cast<uint8_t *>(symbol_table_lookup->second);

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

		// Perform linking
		for (unsigned int i = 0; i < moduleheader.NumberOfSections; i++)
		{
			const IMAGE_SECTION_HEADER &section = section_header_base[i];

			if (section.Characteristics & (IMAGE_SCN_LNK_REMOVE | IMAGE_SCN_MEM_DISCARDABLE) || (section.Characteristics & IMAGE_SCN_CNT_CODE) == 0)
			{
				continue;
			}

			const auto section_relocation_table = reinterpret_cast<const IMAGE_RELOCATION *>(modulebase + section.PointerToRelocations);

			for (unsigned int k = 0; k < section.NumberOfRelocations; k++)
			{
				const IMAGE_RELOCATION &relocation = section_relocation_table[k];
				const auto relocation_address = modulebase + section.PointerToRawData + section.VirtualAddress + relocation.VirtualAddress;
				auto target_address = local_symbol_addresses[relocation.SymbolTableIndex];

#ifdef _M_AMD64
				// Add relay thunk if distance to target exceeds 32 bit range
				if (target_address - relocation_address > 0xFFFFFFFF && ISFCN(symbol_table_base[relocation.SymbolTableIndex].Type))
				{
					assert(additional_data_base + 12 < modulebase + allocsize && "JETLINK: Additional data allocated is not big enough.");

					write_jump(additional_data_base, target_address);

					target_address = additional_data_base;
					additional_data_base += 12;
				}
#endif

				// Update relocations
				switch (relocation.Type)
				{
#ifdef _M_IX86
					case IMAGE_REL_I386_ABSOLUTE: // ignored
						break;
					case IMAGE_REL_I386_DIR32: // absolute virtual address
						*reinterpret_cast<uint32_t *>(relocation_address) = reinterpret_cast<uintptr_t>(target_address);
						break;
					case IMAGE_REL_I386_DIR32NB: // target relative to __ImageBase
						*reinterpret_cast<int32_t *>(relocation_address) = target_address - _imagebase;
						break;
					case IMAGE_REL_I386_REL32: // target relative to next instruction after relocation
						*reinterpret_cast<int32_t *>(relocation_address) = target_address - (relocation_address + 4);
						break;
					case IMAGE_REL_I386_SECTION: // target section index
						*reinterpret_cast<uint16_t *>(relocation_address) = symbol_table_base[relocation.SymbolTableIndex].SectionNumber;
						break;
					case IMAGE_REL_I386_SECREL:
						*reinterpret_cast<int32_t *>(relocation_address) = target_address - (modulebase + section_header_base[symbol_table_base[relocation.SymbolTableIndex].SectionNumber - 1].PointerToRawData);
						break;
#endif
#ifdef _M_AMD64
					case IMAGE_REL_AMD64_ADDR64: // absolute virtual address
						*reinterpret_cast<uint64_t *>(relocation_address) = reinterpret_cast<uintptr_t>(target_address);
						break;
					case IMAGE_REL_AMD64_ADDR32: // absolute virtual address
						assert(reinterpret_cast<uint64_t>(target_address) >> 32 == 0 && "JETLINK: Address overflow in absolute relocation.");
						*reinterpret_cast<uint32_t *>(relocation_address) = reinterpret_cast<uintptr_t>(target_address) & 0xFFFFFFFF;
						break;
					case IMAGE_REL_AMD64_ADDR32NB: // target relative to __ImageBase
						assert(target_address - _imagebase == static_cast<int32_t>(target_address - _imagebase) && "JETLINK: Address overflow in relative relocation.");
						*reinterpret_cast<int32_t *>(relocation_address) = static_cast<int32_t>(target_address - _imagebase);
						break;
					case IMAGE_REL_AMD64_REL32: // target relative to next instruction after relocation
					case IMAGE_REL_AMD64_REL32_1:
					case IMAGE_REL_AMD64_REL32_2:
					case IMAGE_REL_AMD64_REL32_3:
					case IMAGE_REL_AMD64_REL32_4:
					case IMAGE_REL_AMD64_REL32_5:
						assert(target_address - relocation_address == static_cast<int32_t>(target_address - relocation_address) && "JETLINK: Address overflow in relative relocation.");
						*reinterpret_cast<int32_t *>(relocation_address) = static_cast<int32_t>(target_address - (relocation_address + 4 + (relocation.Type - IMAGE_REL_AMD64_REL32)));
						break;
					case IMAGE_REL_AMD64_SECTION: // target section index
						*reinterpret_cast<uint16_t *>(relocation_address) = symbol_table_base[relocation.SymbolTableIndex].SectionNumber;
						break;
					case IMAGE_REL_AMD64_SECREL:
						assert(target_address - _imagebase == static_cast<int32_t>(target_address - (modulebase + section_header_base[symbol_table_base[relocation.SymbolTableIndex].SectionNumber - 1].PointerToRawData)) && "JETLINK: Address overflow in relative relocation.");
						*reinterpret_cast<int32_t *>(relocation_address) = static_cast<int32_t>(target_address - (modulebase + section_header_base[symbol_table_base[relocation.SymbolTableIndex].SectionNumber - 1].PointerToRawData));
						break;
#endif
					default:
						print("JETLINK: Unimplemented relocation type '" + std::to_string(relocation.Type) + "'.\n"); __debugbreak();
				}
			}
		}

		// Reroute old functions to new code
		for (const auto &relocation : image_function_relocations)
		{
			write_jump(relocation.first, relocation.second);
		}

		FlushInstructionCache(GetCurrentProcess(), modulebase, modulesize);

		print("JETLINK: Successfully linked object file into executable image.\n");

		return true;
	}
}
