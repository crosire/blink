/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "blink.hpp"
#include "scoped_handle.hpp"
#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <PathCch.h>
#include <TlHelp32.h> // GetProcessByName

#pragma region CRT sections
// This exists to imitate the behavior of the CRT initialization code
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
extern "C" void _initterm(_PVFV *beg, _PVFV *end);
#pragma endregion

HANDLE console = INVALID_HANDLE_VALUE;
char blink_pipe_name[MAX_PATH];
bool compile_source = true;
#define MAX_ENVIRONMENT_LENGTH 32767 // max for Windows
wchar_t blink_environment[MAX_ENVIRONMENT_LENGTH];
wchar_t blink_working_directory[MAX_PATH];

void print(const char *message, size_t length)
{
	DWORD size = static_cast<DWORD>(length);
	WriteFile(console, message, size, &size, nullptr);
}

static DWORD GetProcessByName(PCSTR name)
{
	WCHAR wide_name[MAX_PATH] = {};
	mbstowcs_s(NULL, wide_name, name, MAX_PATH);

	const scoped_handle snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	// Walk through all processes and search for the name
	PROCESSENTRY32W process = { sizeof(process) };
	for (BOOL next = Process32FirstW(snapshot, &process); next; next = Process32NextW(snapshot, &process))
	{
		if (wcscmp(process.szExeFile, wide_name) == 0)
		{
			return process.th32ProcessID;
		}
	}

	return 0;
}

DWORD CALLBACK remote_main(BYTE *image_base)
{
	#pragma region Initialize module image
	const auto headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(image_base + reinterpret_cast<const IMAGE_DOS_HEADER *>(image_base)->e_lfanew);

	// Apply base relocations
	const auto relocation_delta = image_base - reinterpret_cast<const BYTE *>(headers->OptionalHeader.ImageBase);

	if (relocation_delta != 0) // No need to relocate anything if the delta is zero
	{
		auto relocation = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(image_base + headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

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
					*reinterpret_cast<UINT32 *>(image_base + relocation->VirtualAddress + (field & 0xFFF)) += static_cast<INT32>(relocation_delta);
					break;
				case IMAGE_REL_BASED_DIR64:
					*reinterpret_cast<UINT64 *>(image_base + relocation->VirtualAddress + (field & 0xFFF)) += static_cast<INT64>(relocation_delta);
					break;
				default:
					return ERROR_IMAGE_AT_DIFFERENT_BASE; // Exit when encountering an unknown relocation type
				}
			}

			relocation = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(reinterpret_cast<const BYTE *>(relocation) + relocation->SizeOfBlock);
		}
	}

	// Update import address table (IAT)
	const auto import_directory_entries = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(image_base + headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (size_t i = 0; import_directory_entries[i].FirstThunk != 0; i++)
	{
		const auto name = reinterpret_cast<const char *>(image_base + import_directory_entries[i].Name);
		const auto import_name_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(image_base + import_directory_entries[i].Characteristics);
		const auto import_address_table = reinterpret_cast<IMAGE_THUNK_DATA *>(image_base + import_directory_entries[i].FirstThunk);

		// It is safe to call 'LoadLibrary' here because the IAT entry for it was copied from the parent process and KERNEL32.dll is always loaded at the same address
		const HMODULE module = LoadLibraryA(name);

		if (module == nullptr)
			continue;

		for (size_t k = 0; import_name_table[k].u1.AddressOfData != 0; k++)
		{
			if (IMAGE_SNAP_BY_ORDINAL(import_name_table[k].u1.Ordinal))
			{
				// Import by ordinal
				const auto import = IMAGE_ORDINAL(import_name_table[k].u1.Ordinal);

				import_address_table[k].u1.AddressOfData = reinterpret_cast<DWORD_PTR>(GetProcAddress(module, reinterpret_cast<LPCSTR>(import)));
			}
			else
			{
				// Import by function name
				const auto import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(image_base + import_name_table[k].u1.AddressOfData);

				import_address_table[k].u1.AddressOfData = reinterpret_cast<DWORD_PTR>(GetProcAddress(module, import->Name));
			}
		}
	}

	// Call global C/C++ constructors
	_initterm(__xi_a, __xi_z);
	_initterm(__xc_a, __xc_z);
	#pragma endregion

	scoped_handle blink_handle = CreateFileA(blink_pipe_name, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, FILE_FLAG_WRITE_THROUGH, NULL);

	// Run main loop
	blink::application().run(blink_handle, blink_environment, blink_working_directory, compile_source);

	CloseHandle(console);

	return 0;
}

int main(int argc, char *argv[])
{
	DWORD pid = 0;

	if (argc > 1)
	{
		int i = 1;

		for (; i < argc; i++)
		{
			if (std::strcmp(argv[i], "-h") == 0 || std::strcmp(argv[i], "--help") == 0)
			{
				std::cout << "usage: " << argv[0] << " [options] <...>" << std::endl;
				std::cout << "  <...>              PID or name of running process, or command-line of target application to launch" << std::endl;
				std::cout << "  -h/--help          Show this help message" << std::endl;
				std::cout << "  --no-compile       Watch for changes to object files and link them directly, rather than source files and compiling them first" << std::endl;
				return 0;
			}
			if (std::strcmp(argv[i], "--no-compile") == 0)
			{
				compile_source = false;
				continue;
			}

			// Argument is not an option, so assume this starts the remaining command-line
			break;
		}

		// Attach to running process by PID
		pid = std::strtoul(argv[i], nullptr, 0);

		if (pid == 0)
		{
			// Try to look up PID of running process by name
			pid = GetProcessByName(argv[i]);
		}

		if (pid == 0)
		{
			// Launch target application with remaining command-line and determine PID
			STARTUPINFOA startup_info = { sizeof(startup_info) };
			PROCESS_INFORMATION process_info = {};

			std::string command_line;
			for (; i < argc; ++i, command_line += ' ')
				command_line += argv[i];

			if (!CreateProcessA(nullptr, command_line.data(), nullptr, nullptr, FALSE, CREATE_NEW_CONSOLE, nullptr, nullptr, &startup_info, &process_info))
			{
				std::cout << "Failed to start target application process!" << std::endl;
				return GetLastError();
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
	const HANDLE local_process = GetCurrentProcess();
	const scoped_handle remote_process = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION, FALSE, pid);

	if (remote_process == nullptr)
	{
		std::cout << "Failed to open target application process!" << std::endl;
		return GetLastError();
	}

	BOOL local_is_wow64 = FALSE, remote_is_wow64 = FALSE;
	IsWow64Process(local_process, &local_is_wow64);
	IsWow64Process(remote_process, &remote_is_wow64);

	if (local_is_wow64 != remote_is_wow64)
	{
		std::cout << "Machine architecture mismatch between target application and this application!" << std::endl;
		return ERROR_IMAGE_MACHINE_TYPE_MISMATCH;
	}

	std::cout << "Launching in target application ..." << std::endl;

	// Create a pipe for communication between this process and the target application
	scoped_handle local_pipe;
	if (!CreatePipe(&local_pipe, &console, nullptr, 512) || !DuplicateHandle(local_process, console, remote_process, &console, 0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
	{
		std::cout << "Failed to create new communication pipe!" << std::endl;
		return GetLastError();
	}

	MODULEINFO module_info;
	if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle(nullptr), &module_info, sizeof(module_info)))
		return GetLastError();

#ifdef _DEBUG // Use 'LoadLibrary' to create image in target application so that debug information is loaded
	WCHAR load_path[MAX_PATH];
	WCHAR load_path_canonicalized[MAX_PATH];
	GetModuleFileNameW(nullptr, load_path, MAX_PATH);
	PathCchCanonicalize(load_path_canonicalized, MAX_PATH, load_path);

	const auto load_param = VirtualAllocEx(remote_process, nullptr, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// Write 'LoadLibrary' call argument to target application
	if (load_param == nullptr || !WriteProcessMemory(remote_process, load_param, load_path, MAX_PATH, nullptr))
	{
		std::cout << "Failed to allocate and write 'LoadLibrary' argument in target application!" << std::endl;
		return GetLastError();
	}

	// Execute 'LoadLibrary' in target application
	const scoped_handle load_thread = CreateRemoteThread(remote_process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(&LoadLibraryW), load_param, 0, nullptr);

	if (load_thread == nullptr)
	{
		std::cout << "Failed to execute 'LoadLibrary' in target application!" << std::endl;
		return GetLastError();
	}

	// Wait for loading to finish and clean up parameter memory afterwards
	WaitForSingleObject(load_thread, INFINITE);
	VirtualFreeEx(remote_process, load_param, 0, MEM_RELEASE);

	// Find address of the now loaded module in the target application process
	DWORD modules_size = 0;
	EnumProcessModulesEx(remote_process, nullptr, 0, &modules_size, LIST_MODULES_ALL);
	std::vector<HMODULE> modules(modules_size / sizeof(HMODULE));
	EnumProcessModulesEx(remote_process, modules.data(), modules_size, &modules_size, LIST_MODULES_ALL);

	BYTE *remote_baseaddress = nullptr;

	for (HMODULE module : modules)
	{
		WCHAR module_path[MAX_PATH];
		WCHAR module_path_canonicalized[MAX_PATH];
		GetModuleFileNameExW(remote_process, module, module_path, MAX_PATH);
		PathCchCanonicalize(module_path_canonicalized, MAX_PATH, module_path);

		if (lstrcmpW(module_path_canonicalized, load_path_canonicalized) == 0)
		{
			remote_baseaddress = reinterpret_cast<BYTE *>(module);
			break;
		}
	}

	// Make the entire image writable so the copy operation below can succeed
	if (remote_baseaddress != nullptr)
	{
		VirtualProtectEx(remote_process, remote_baseaddress, module_info.SizeOfImage, PAGE_EXECUTE_READWRITE, &modules_size);
	}
#else
	const auto remote_baseaddress = static_cast<BYTE *>(VirtualAllocEx(remote_process, nullptr, module_info.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
#endif

	_snprintf_s(blink_pipe_name, sizeof(blink_pipe_name), "\\\\.\\pipe\\blink-%d", GetCurrentProcessId());
#define NAMED_PIPE_SIZE 1024
	// use duplex named pipe, so remote thread can quit and free up memory, when blink.exe quits
	scoped_handle blink_pipe_handle = CreateNamedPipeA(
		reinterpret_cast<LPCSTR>(blink_pipe_name),
		PIPE_ACCESS_DUPLEX
		| FILE_FLAG_WRITE_THROUGH,
		PIPE_TYPE_BYTE | PIPE_WAIT,
		1, NAMED_PIPE_SIZE, NAMED_PIPE_SIZE,
		10000, NULL);
	if (!blink_pipe_handle)
	{
		std::cout << "Failed to create blink pipe!" << std::endl;
		return GetLastError();
	}

	// Get blink.exe's environment, so we can use it for compiles in the remote thread.
	const LPWCH environment = GetEnvironmentStringsW();
	LPWCH environment_end = environment;
	for (; *environment_end != '\0'; environment_end += wcslen(environment_end) + 1)
	{
		// continue until we find the double null end
	}
	environment_end += 1; // get position after the double null end
	const size_t environment_length = environment_end - environment;
	if (environment_length > MAX_ENVIRONMENT_LENGTH)
	{
		std::cout << "Environment string exceeded max length!" << std::endl;
		return ERROR_NOT_ENOUGH_MEMORY;
	}
	memcpy(blink_environment, environment, environment_length * sizeof(wchar_t));
	FreeEnvironmentStringsW(environment);

	// Get blink.exe's working directory, so we can use it for compiles in the remote thread.
	wcscpy_s(blink_working_directory, std::filesystem::current_path().c_str());

	// Copy current module image to target application (including the IAT and value of the global variables)
	if (remote_baseaddress == nullptr || !WriteProcessMemory(remote_process, remote_baseaddress, module_info.lpBaseOfDll, module_info.SizeOfImage, nullptr))
	{
		std::cout << "Failed to allocate and write image in target application!" << std::endl;
		return GetLastError();
	}

	// Launch module main entry point in target application
	const auto remote_entrypoint = remote_baseaddress + (reinterpret_cast<BYTE *>(&remote_main) - static_cast<BYTE *>(module_info.lpBaseOfDll));
	std::cout << "  Entry point was written to address " << static_cast<const void *>(remote_baseaddress) << std::endl;
	const scoped_handle remote_thread = CreateRemoteThread(remote_process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_entrypoint), remote_baseaddress, 0, nullptr);

	if (remote_thread == nullptr)
	{
		std::cout << "Failed to launch remote thread in target application!" << std::endl;
		return GetLastError();
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

	std::cout << "The target application has exited with code " << remote_exitcode << "." << std::endl;

	return static_cast<int>(exitcode);
}
