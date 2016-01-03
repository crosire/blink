#include "jetlink.hpp"

#include <Windows.h>
#include <Psapi.h>
#include <iostream>

#pragma region CRT sections
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

void pause()
{
	DWORD mode;
	const HANDLE console = GetStdHandle(STD_INPUT_HANDLE);

	if (!GetConsoleMode(console, &mode) || !SetConsoleMode(console, 0))
	{
		return;
	}

	FlushConsoleInputBuffer(console);

	INPUT_RECORD input;

	do
	{
		DWORD count;
		ReadConsoleInput(console, &input, 1, &count);
	}
	while (input.EventType != KEY_EVENT || input.Event.KeyEvent.bKeyDown);

	SetConsoleMode(console, mode);
}
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

	while (relocation->VirtualAddress != 0)
	{
		const auto field_count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

		for (size_t k = 0; k < field_count; k++)
		{
			const auto field = reinterpret_cast<const WORD *>(relocation + 1)[k];

			const auto type = field >> 12;
			const auto offset = field & 0xFFF;

			switch (type)
			{
				case IMAGE_REL_BASED_ABSOLUTE:
					break;
				case IMAGE_REL_BASED_HIGHLOW:
					*reinterpret_cast<UINT32 *>(imagebase + relocation->VirtualAddress + offset) += static_cast<INT32>(relocation_delta);
					break;
				case IMAGE_REL_BASED_DIR64:
					*reinterpret_cast<UINT64 *>(imagebase + relocation->VirtualAddress + offset) += static_cast<INT64>(relocation_delta);
					break;
				default:
					return 1;
			}
		}

		relocation = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(reinterpret_cast<const BYTE *>(relocation) + relocation->SizeOfBlock);
	}

	// Resolve imports
	const auto import_directory_entries = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(imagebase + imageheaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (size_t i = 0; import_directory_entries[i].FirstThunk != 0; i++)
	{
		const auto name = reinterpret_cast<const char *>(imagebase + import_directory_entries[i].Name);
		const auto import_name_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(imagebase + import_directory_entries[i].Characteristics);
		const auto import_address_table = reinterpret_cast<IMAGE_THUNK_DATA *>(imagebase + import_directory_entries[i].FirstThunk);

		const HMODULE module = LoadLibraryA(name);

		if (module == nullptr)
		{
			continue;
		}

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
	jetlink::application().run();

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
	}
	if (pid == 0)
	{
		std::cout << "Enter PID of target application: ";
		std::cin >> pid;
	}

	const HANDLE local_process = GetCurrentProcess();
	const HANDLE remote_process = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);

	if (remote_process == nullptr)
	{
		std::cout << "Failed to open target application process!";

		return 1;
	}

	BOOL local_is_wow64 = FALSE, remote_is_wow64 = FALSE;
	IsWow64Process(local_process, &local_is_wow64);
	IsWow64Process(remote_process, &remote_is_wow64);

	if (local_is_wow64 != remote_is_wow64)
	{
		CloseHandle(remote_process);

		std::cout << "Machine architecture mismatch between target application and this application!";

		return 2;
	}

	std::cout << "Launching in target application [" << pid << "] ..." << std::endl;

	// Create a pipe for communication between this process and the target application
	HANDLE local_pipe = INVALID_HANDLE_VALUE;

	if (!CreatePipe(&local_pipe, &console, nullptr, 512) || !DuplicateHandle(local_process, console, remote_process, &console, 0, FALSE, DUPLICATE_CLOSE_SOURCE | DUPLICATE_SAME_ACCESS))
	{
		std::cout << "Failed to create new communication pipe!";

		return 1;
	}

	// Allocate memory in target application
	MODULEINFO moduleinfo;

	if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandle(nullptr), &moduleinfo, sizeof(moduleinfo)))
	{
		return 1;
	}

	const auto remote_baseaddress = static_cast<unsigned char *>(VirtualAllocEx(remote_process, nullptr, moduleinfo.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));

	if (remote_baseaddress == nullptr)
	{
		std::cout << "Failed to allocate memory in target application!";

		return 1;
	}

	// Write module image to target application (including the value of the global 'console' variable)
	SIZE_T written = 0;

	if (!WriteProcessMemory(remote_process, remote_baseaddress, moduleinfo.lpBaseOfDll, moduleinfo.SizeOfImage, &written) || written < moduleinfo.SizeOfImage)
	{
		std::cout << "Failed to write module image to target application!";

		return 1;
	}

	// Launch module main entry point in target application
	const auto remote_entrypoint = remote_baseaddress + (reinterpret_cast<unsigned char *>(&remote_main) - static_cast<unsigned char *>(moduleinfo.lpBaseOfDll));
	const HANDLE remote_thread = CreateRemoteThread(remote_process, nullptr, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(remote_entrypoint), remote_baseaddress, 0, nullptr);

	if (remote_thread == nullptr)
	{
		std::cout << "Failed to launch remote thread in target application!";

		return 1;
	}

	// Run main loop and pass on incoming messages to console
	while (WaitForSingleObject(remote_thread, 0))
	{
		DWORD size = 512;
		char message[512];

		if (!ReadFile(local_pipe, message, size, &size, nullptr))
		{
			continue;
		}

		WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), message, size, &size, nullptr);
	}

	DWORD exitcode = 0;
	GetExitCodeThread(remote_thread, &exitcode);

	// Clean up handles
	CloseHandle(local_pipe);
	CloseHandle(remote_thread);
	CloseHandle(remote_process);

	// Exit
	std::cout << "The target application has exited. Press any key to continue ...";

	pause();

	return static_cast<int>(exitcode);
}
