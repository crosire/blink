#include "jetlink.hpp"

#include <assert.h>
#include <vector>
#include <fstream>
#include <algorithm>
#include <Windows.h>

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	_Field_size_bytes_part_(MaximumLength, Length) PWCH Buffer;
} UNICODE_STRING;
typedef UNICODE_STRING *PUNICODE_STRING;
typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE
} OBJECT_ATTRIBUTES;
typedef OBJECT_ATTRIBUTES *POBJECT_ATTRIBUTES;
typedef CONST OBJECT_ATTRIBUTES *PCOBJECT_ATTRIBUTES;
typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2
} SECTION_INHERIT, *PSECTION_INHERIT;

typedef NTSTATUS (NTAPI *tNtCreateSection)(PHANDLE SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG PageAttributess, ULONG SectionAttributes, HANDLE FileHandle);
typedef NTSTATUS (NTAPI *tNtMapViewOfSection)(HANDLE SectionHandle, HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, SECTION_INHERIT InheritDisposition, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS (NTAPI *tNtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS (NTAPI *tNtClose)(HANDLE Handle);

namespace jetlink
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
				if (VirtualQuery(address, &meminfo, sizeof(meminfo)) == 0)
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
		DWORD round_to_multiple(DWORD value, DWORD multiple)
		{
			return ((value + multiple - 1) / multiple) * multiple;
		}
	}

	bool application::link(const std::string &path)
	{
		// Open object file
		const HANDLE objectfile = CreateFileA(path.c_str(), FILE_GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);

		if (objectfile == INVALID_HANDLE_VALUE)
		{
			print("JETLINK: Failed to open input file.\n");

			return false;
		}

		const auto objectsize = GetFileSize(objectfile, nullptr);

		// Create temporary module file for mapping
		//const HANDLE modulefile = CreateFileA("jetlink_temp.dll", FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_EXECUTE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_RANDOM_ACCESS, nullptr);
		const HANDLE modulefile = CreateFileA(path.c_str(), FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_EXECUTE, 0, nullptr, OPEN_EXISTING, FILE_FLAG_RANDOM_ACCESS, nullptr);

		if (modulefile == INVALID_HANDLE_VALUE)
		{
			CloseHandle(objectfile);

			print("JETLINK: Failed to create temporary module file.\n");

			return false;
		}

		// Write PE headers to module file
		DWORD written = 0;
		IMAGE_DOS_HEADER stub_dll_header1 = { };
		stub_dll_header1.e_magic = IMAGE_DOS_SIGNATURE;
		stub_dll_header1.e_lfanew = sizeof(stub_dll_header1);
		IMAGE_NT_HEADERS stub_dll_header2 = { };
		stub_dll_header2.Signature = IMAGE_NT_SIGNATURE;
		ReadFile(objectfile, &stub_dll_header2.FileHeader, sizeof(stub_dll_header2.FileHeader), &written, nullptr);
		const auto num_sections = stub_dll_header2.FileHeader.NumberOfSections;
		stub_dll_header2.FileHeader.NumberOfSections = 1;
		stub_dll_header2.FileHeader.SizeOfOptionalHeader = sizeof(stub_dll_header2.OptionalHeader);
		stub_dll_header2.FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_DLL | IMAGE_FILE_RELOCS_STRIPPED;
		stub_dll_header2.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR_MAGIC;
		stub_dll_header2.OptionalHeader.SizeOfCode = 0;
		stub_dll_header2.OptionalHeader.SizeOfInitializedData = 512;
		stub_dll_header2.OptionalHeader.SizeOfUninitializedData = 0;
		stub_dll_header2.OptionalHeader.AddressOfEntryPoint = 0;
		stub_dll_header2.OptionalHeader.BaseOfCode = 0;
#ifdef _M_IX86
		stub_dll_header2.OptionalHeader.BaseOfData = 0;
#endif
		stub_dll_header2.OptionalHeader.ImageBase = 0x80000000;
		stub_dll_header2.OptionalHeader.SectionAlignment = 4096;
		stub_dll_header2.OptionalHeader.FileAlignment = 512;
		stub_dll_header2.OptionalHeader.MajorOperatingSystemVersion = stub_dll_header2.OptionalHeader.MajorSubsystemVersion = 6;
		stub_dll_header2.OptionalHeader.MinorOperatingSystemVersion = stub_dll_header2.OptionalHeader.MinorSubsystemVersion = 0;
		stub_dll_header2.OptionalHeader.SizeOfImage = 8192;// round_to_multiple(sizeof(stub_dll_header1) + sizeof(stub_dll_header2), stub_dll_header2.OptionalHeader.SectionAlignment);
		stub_dll_header2.OptionalHeader.SizeOfHeaders = round_to_multiple(sizeof(stub_dll_header1) + sizeof(stub_dll_header2), stub_dll_header2.OptionalHeader.FileAlignment);
		stub_dll_header2.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
		stub_dll_header2.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
		stub_dll_header2.OptionalHeader.SizeOfStackReserve = 0x100000;
		stub_dll_header2.OptionalHeader.SizeOfStackCommit = 0x1000;
		stub_dll_header2.OptionalHeader.SizeOfHeapReserve = 0x100000;
		stub_dll_header2.OptionalHeader.SizeOfHeapCommit = 0x1000;
		stub_dll_header2.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

		IMAGE_SECTION_HEADER stub_dll_section1 = { };
		stub_dll_section1.Name[0] = '.', stub_dll_section1.Name[1] = 'r', stub_dll_section1.Name[2] = 'd', stub_dll_section1.Name[3] = 'a', stub_dll_section1.Name[4] = 't', stub_dll_section1.Name[5] = 'a';
		stub_dll_section1.Misc.PhysicalAddress = 0x64;
		stub_dll_section1.VirtualAddress = stub_dll_header2.OptionalHeader.SectionAlignment;
		stub_dll_section1.SizeOfRawData = round_to_multiple(objectsize, stub_dll_header2.OptionalHeader.FileAlignment);
		stub_dll_section1.PointerToRawData = stub_dll_header2.OptionalHeader.BaseOfCode = stub_dll_header2.OptionalHeader.SizeOfHeaders;
		stub_dll_section1.Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE;

		std::vector<IMAGE_DEBUG_DIRECTORY> debug_directory = { };

		stub_dll_header2.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = sizeof(stub_dll_header1) + sizeof(stub_dll_header2) + sizeof(stub_dll_section1) + num_sections * sizeof(IMAGE_SECTION_HEADER);
		stub_dll_header2.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size = 0;

		WriteFile(modulefile, &stub_dll_header1, sizeof(stub_dll_header1), &written, nullptr);
		WriteFile(modulefile, &stub_dll_header2, sizeof(stub_dll_header2), &written, nullptr);
		WriteFile(modulefile, &stub_dll_section1, sizeof(stub_dll_section1), &written, nullptr);

		// Write section headers
		size_t uninitialized_data_size = 0, additional_data_size = 0;

		for (DWORD i = num_sections, readwrite; i > 0; i--)
		{
			IMAGE_SECTION_HEADER section;

			if (!ReadFile(objectfile, &section, sizeof(section), &readwrite, nullptr))
			{
				break;
			}

			if (section.PointerToRawData == 0 && section.Characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA)
			{
				// Create uninitialized data sections
				section.PointerToRawData = objectsize + uninitialized_data_size;

				uninitialized_data_size += section.SizeOfRawData;
			}
#ifdef _M_AMD64
			else if (section.Characteristics & IMAGE_SCN_CNT_CODE)
			{
				additional_data_size += section.NumberOfRelocations * 12;
			}
#endif
			else if (strncmp(reinterpret_cast<const char *>(section.Name), ".debug", IMAGE_SIZEOF_SHORT_NAME) == 0)
			{
				IMAGE_DEBUG_DIRECTORY debug_entry = { };
				debug_entry.MajorVersion = 4;
				debug_entry.Type = IMAGE_DEBUG_TYPE_CODEVIEW;
				debug_entry.SizeOfData = section.SizeOfRawData;
				debug_entry.AddressOfRawData = section.PointerToRawData;
				debug_entry.PointerToRawData = section.PointerToRawData;

				debug_directory.push_back(std::move(debug_entry));
			}

			// Executables do not support long section names
			assert(section.Name[0] != '/');

			section.Misc.VirtualSize = section.SizeOfRawData;

			// Fix up file offsets
			if (section.PointerToRawData != 0)
			{
				section.PointerToRawData += sizeof(stub_dll_header1) + 4 + stub_dll_header2.FileHeader.SizeOfOptionalHeader;
			}
			if (section.PointerToRelocations != 0)
			{
				section.PointerToRelocations += sizeof(stub_dll_header1) + 4 + stub_dll_header2.FileHeader.SizeOfOptionalHeader;
			}
			if (section.PointerToLinenumbers != 0)
			{
				section.PointerToLinenumbers += sizeof(stub_dll_header1) + 4 + stub_dll_header2.FileHeader.SizeOfOptionalHeader;
			}

			section.VirtualAddress = section.PointerToRawData;

			if (!WriteFile(modulefile, &section, sizeof(section), &readwrite, nullptr))
			{
				break;
			}
		}

		// Write section contents
		BYTE buffer[512];
		DWORD readwrite = 0;
		while (ReadFile(objectfile, buffer, sizeof(buffer), &readwrite, nullptr) && readwrite != 0)
		{
			WriteFile(modulefile, buffer, readwrite, &readwrite, nullptr);
		}

		// Write debug directory
		for (const auto &debug_entry : debug_directory)
		{
			WriteFile(modulefile, &debug_entry, sizeof(debug_entry), &readwrite, nullptr);
		}

		// Allocate additional data
		for (size_t i = 0; i < uninitialized_data_size + additional_data_size; i++)
		{
			DWORD a = 0;
			WriteFile(modulefile, &a, 1, &a, nullptr);
		}

		// Close object file
		//CloseHandle(objectfile);

		// Create module file mapping
		//const HANDLE filemapping = CreateFileMappingA(modulefile, nullptr, SEC_IMAGE | PAGE_EXECUTE_READWRITE, 0, 0, nullptr);
		const HANDLE filemapping = CreateFileMappingA(modulefile, nullptr, PAGE_EXECUTE_READWRITE, 0, 0, nullptr);

		if (filemapping == nullptr)
		{
			CloseHandle(modulefile);

			print("JETLINK: Failed to create temporary module file mapping.\n");

			return false;
		}

		// Allocate executable memory region close to the executable image base.
		// Successfully loaded object files are never deallocated again to avoid corrupting the function rerouting generated below.
		// The virtual memory is freed at process exit by Windows.
		//const auto modulebase = static_cast<uint8_t *>(VirtualAlloc(find_free_memory_region(_imagebase, allocsize), allocsize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE));
		// MapViewOfFileEx calls NtMapViewOfSection under the hood, which calls the debug LoadImageNotifyRoutine callback
		const auto modulebase = static_cast<uint8_t *>(MapViewOfFileEx(filemapping, FILE_MAP_READ | FILE_MAP_WRITE | FILE_MAP_EXECUTE, 0, 0, 0, nullptr));
		const auto modulesize = GetFileSize(modulefile, nullptr);

		CloseHandle(filemapping);

		if (modulebase == nullptr)
		{
			CloseHandle(modulefile);

			print("JETLINK: Failed to allocate executable memory region.\n");

			return false;
		}

		//const auto &moduleheader = *reinterpret_cast<const IMAGE_FILE_HEADER *>(modulebase + reinterpret_cast<const IMAGE_DOS_HEADER *>(modulebase)->e_lfanew + 4);
		const auto &moduleheader = *reinterpret_cast<const IMAGE_FILE_HEADER *>(modulebase);

#ifdef _M_IX86
		if (moduleheader.Machine != IMAGE_FILE_MACHINE_I386)
#endif
#ifdef _M_AMD64
		if (moduleheader.Machine != IMAGE_FILE_MACHINE_AMD64)
#endif
		{
			UnmapViewOfFile(modulebase);
			CloseHandle(modulefile);

			print("JETLINK: Input file is not of a valid format or was compiled for a different processor architecture.\n");

			return false;
		}

		auto additional_data_base = modulebase + modulesize;// -additional_data_size;
		const auto symbol_table_base = reinterpret_cast<const IMAGE_SYMBOL *>(modulebase + moduleheader.PointerToSymbolTable);
		const auto section_header_base = reinterpret_cast<IMAGE_SECTION_HEADER *>(modulebase + sizeof(IMAGE_FILE_HEADER) + moduleheader.SizeOfOptionalHeader);
		std::vector<uint8_t *> local_symbol_addresses(moduleheader.NumberOfSymbols);
		std::vector<std::pair<uint8_t *, const uint8_t *>> image_function_relocations;

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
					UnmapViewOfFile(modulebase);
					CloseHandle(modulefile);

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
					UnmapViewOfFile(modulebase);
					CloseHandle(modulefile);

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
					//assert(additional_data_base + 12 < modulebase + allocsize && "JETLINK: Additional data allocated is not big enough.");

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
