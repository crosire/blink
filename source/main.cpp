/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "blink.hpp"
#include <Windows.h>
#include <Psapi.h>
#include <iostream>

#pragma region CRT sections
// This exists to imitate the behavior of the Visual C++ CRT initialization code
#pragma section(".CRT$XIA", long, read)
#pragma section(".CRT$XIZ", long, read)
#pragma section(".CRT$XCA", long, read)
#pragma section(".CRT$XCZ", long, read)
#pragma comment(linker, "/merge:.CRT=.rdata")
typedef void(__cdecl *_PVFV)();
__declspec(allocate(".CRT$XIA")) _PVFV __xi_a[] = { nullptr };
__declspec(allocate(".CRT$XIZ")) _PVFV __xi_z[] = { nullptr };
__declspec(allocate(".CRT$XCA")) _PVFV __xc_a[] = { nullptr };
__declspec(allocate(".CRT$XCZ")) _PVFV __xc_z[] = { nullptr };

inline void _initterm(_PVFV *beg, _PVFV *end)
{
	for (; beg < end; beg++)
		if (*beg)
			(**beg)();
}
#pragma endregion

HANDLE console = INVALID_HANDLE_VALUE;

void print(const char *message, size_t length)
{
	DWORD size = static_cast<DWORD>(length);
	WriteFile(console, message, size, &size, nullptr);
}

DWORD CALLBACK remote_main(BYTE *imagebase)
{
	#pragma region Initialize module image
	const auto imageheaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(imagebase + reinterpret_cast<const IMAGE_DOS_HEADER *>(imagebase)->e_lfanew);

	// Apply base relocations
	auto relocation = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(imagebase + imageheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
	const auto relocation_delta = imagebase - reinterpret_cast<const BYTE *>(imageheaders->OptionalHeader.ImageBase);

	if (relocation_delta != 0) // No need to relocate anything if the delta is zero
	{
		while (relocation->VirtualAddress != 0)
		{
			const auto field_count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

			for (size_t k = 0; k < field_count; k++)
			{
				const WORD field = reinterpret_cast<const WORD *>(relocation + 1)[k];

				switch (field >> 12)
				{
				case IMAGE_REL_BASED_ABSOLUTE:
					break; // This one does not do anything and exists only for table alignment, so ignore it
				case IMAGE_REL_BASED_HIGHLOW:
					*reinterpret_cast<UINT32 *>(imagebase + relocation->VirtualAddress + (field & 0xFFF)) += static_cast<INT32>(relocation_delta);
					break;
				case IMAGE_REL_BASED_DIR64:
					*reinterpret_cast<UINT64 *>(imagebase + relocation->VirtualAddress + (field & 0xFFF)) += static_cast<INT64>(relocation_delta);
					break;
				default:
					return 1; // Exit when encountering an unknown relocation type
				}
			}

			relocation = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(reinterpret_cast<const BYTE *>(relocation) + relocation->SizeOfBlock);
		}
	}

	// Update import address table (IAT)
	const auto import_directory_entries = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(imagebase + imageheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (size_t i = 0; import_directory_entries[i].FirstThunk != 0; i++)
	{
		const auto name = reinterpret_cast<const char *>(imagebase + import_directory_entries[i].Name);
		const auto import_name_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(imagebase + import_directory_entries[i].Characteristics);
		const auto import_address_table = reinterpret_cast<IMAGE_THUNK_DATA *>(imagebase + import_directory_entries[i].FirstThunk);

		// It is safe to call 'LoadLibrary' here because the IAT entry for it was copied from the parent process and KERNEL32.dll is always loaded at the same address
		const HMODULE module = LoadLibraryA(name);

		if (module == nullptr)
			continue;

		for (size_t k = 0; import_name_table[k].u1.AddressOfData != 0; k++)
		{
			const auto import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(imagebase + import_name_table[k].u1.AddressOfData);

			import_address_table[k].u1.AddressOfData = reinterpret_cast<DWORD_PTR>(GetProcAddress(module, import->Name));
		}
	}

	// Call constructors
	_initterm(__xi_a, __xi_z);
	_initterm(__xc_a, __xc_z);
	#pragma endregion

	// Small timeout to prevent race condition
	Sleep(100);

	// Run main loop
	blink::application().run();

	// Small timeout to prevent race condition
	Sleep(100);

	// Clean up handles
	CloseHandle(console);

	return 0;
}

int main(int argc, char *argv[])
{
	DWORD pid = 0;

	if (argc > 1)
	{
		pid = strtoul(argv[1], nullptr, 0);

		if (pid == 0)
		{
			STARTUPINFOA startup_info = { sizeof(startup_info) };
			PROCESS_INFORMATION process_info = {};

			std::string command_line;
			for (int i = 1; i < argc; ++i, command_line += ' ')
				command_line += argv[i];

			if (!CreateProcessA(nullptr, const_cast<char *>(command_line.data()), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &startup_info, &process_info))
			{
				std::cout << "Failed to start target application process!" << std::endl;
				return 1;
			}

			pid = process_info.dwProcessId;

			CloseHandle(process_info.hThread);
			CloseHandle(process_info.hProcess);
		}
	}

	if (pid == 0)
	{
		std::cout << "Enter PID of target application: ";
		std::cin >> pid;
	}

	// Open target application process
	const DWORD access = PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION;
	const HANDLE local_process = GetCurrentProcess();
	const HANDLE remote_process = OpenProcess(access, FALSE, pid);

	if (remote_process == nullptr)
	{
		std::cout << "Failed to open target application process!" << std::endl;
		return 1;
	}

	BOOL local_is_wow64 = FALSE, remote_is_wow64 = FALSE;
	IsWow64Process(local_process, &local_is_wow64);
	IsWow64Process(remote_process, &remote_is_wow64);

	if (local_is_wow64 != remote_is_wow64)
	{
		CloseHandle(remote_process);

		std::cout << "Machine architecture mismatch between target application and this application!" << std::endl;
		return 2;
	}

	std::cout << "Launching in target application ..." << std::endl;

	// Create a pipe for communication between this process and the target application
	HANDLE local_pipe = INVALID_HANDLE_VALUE;

	if (!CreatePipe(&local_pipe, &console, nullptr, 512) || !DuplicateHandle(local_process, console, remote_process, &console, 0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
	{
		std::cout << "Failed to create new communication pipe!" << std::endl;
		return 1;
	}

	MODULEINFO moduleinfo;
	if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle(nullptr), &moduleinfo, sizeof(moduleinfo)))
		return 1;

#ifdef _DEBUG // Use 'LoadLibrary' to create image in target application so that debug information is loaded
	TCHAR load_path[MAX_PATH];
	GetModuleFileName(nullptr, load_path, MAX_PATH);

	const auto load_param = VirtualAllocEx(remote_process, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Write 'LoadLibrary' call argument to target application
	if (load_param == nullptr || !WriteProcessMemory(remote_process, load_param, load_path, MAX_PATH, nullptr))
	{
		std::cout << "Failed to allocate and write 'LoadLibrary' argument in target application!" << std::endl;
		return 1;
	}

	// Execute 'LoadLibrary' in target application
	const HANDLE load_thread = CreateRemoteThread(remote_process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&LoadLibrary), load_param, 0, nullptr);

	if (load_thread == nullptr)
	{
		std::cout << "Failed to execute 'LoadLibrary' in target application!" << std::endl;
		return 1;
	}

	// Wait for loading to finish and clean up parameter memory afterwards
	WaitForSingleObject(load_thread, INFINITE);
	CloseHandle(load_thread);
	VirtualFreeEx(remote_process, load_param, 0, MEM_RELEASE);

	// Find address of the now loaded module in the target application process
	DWORD modules_size = 0;
	EnumProcessModulesEx(remote_process, nullptr, 0, &modules_size, LIST_MODULES_ALL);
	std::vector<HMODULE> modules(modules_size / sizeof(HMODULE));
	EnumProcessModulesEx(remote_process, modules.data(), modules_size, &modules_size, LIST_MODULES_ALL);

	BYTE *remote_baseaddress = nullptr;

	for (HMODULE module : modules)
	{
		TCHAR module_path[MAX_PATH];
		GetModuleFileNameEx(remote_process, module, module_path, sizeof(module_path));

		if (lstrcmp(module_path, load_path) == 0)
		{
			remote_baseaddress = reinterpret_cast<BYTE *>(module);
			break;
		}
	}

	// Make the entire image writable so the copy operation below can succeed
	VirtualProtectEx(remote_process, remote_baseaddress, moduleinfo.SizeOfImage, PAGE_EXECUTE_READWRITE, &modules_size);
#else
	const auto remote_baseaddress = static_cast<BYTE *>(VirtualAllocEx(remote_process, nullptr, moduleinfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
#endif

	// Copy current module image to target application (including the IAT and value of the global 'console' variable)
	if (remote_baseaddress == nullptr || !WriteProcessMemory(remote_process, remote_baseaddress, moduleinfo.lpBaseOfDll, moduleinfo.SizeOfImage, nullptr))
	{
		std::cout << "Failed to allocate and write image in target application!" << std::endl;
		return 1;
	}

	// Launch module main entry point in target application
	const auto remote_entrypoint = remote_baseaddress + (reinterpret_cast<BYTE *>(&remote_main) - static_cast<BYTE *>(moduleinfo.lpBaseOfDll));
	std::cout << "  Entry point was written to address " << static_cast<const void *>(remote_baseaddress) << std::endl;
	const HANDLE remote_thread = CreateRemoteThread(remote_process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_entrypoint), remote_baseaddress, 0, nullptr);

	if (remote_thread == nullptr)
	{
		std::cout << "Failed to launch remote thread in target application!" << std::endl;
		return 1;
	}

	// Run main loop and pass on incoming messages to console
	while (WaitForSingleObject(remote_thread, 0))
	{
		char message[512] = "";
		DWORD size = ARRAYSIZE(message);

		if (!ReadFile(local_pipe, message, size, &size, nullptr) || size == 0)
			continue;

		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, size, &size, nullptr);
	}

	DWORD exitcode = 0, remote_exitcode = 0;
	GetExitCodeThread(remote_thread, &exitcode);
	GetExitCodeProcess(remote_process, &remote_exitcode);

	// Clean up handles
	CloseHandle(local_pipe);
	CloseHandle(remote_thread);
	CloseHandle(remote_process);

	// Exit
	std::cout << "The target application has exited with code " << remote_exitcode << "." << std::endl;

	return static_cast<int>(exitcode);
}
