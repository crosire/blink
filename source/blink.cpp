/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "blink.hpp"
#include "pdb_reader.hpp"
#include "file_watcher.hpp"
#include <string>
#include <atomic>
#include <unordered_map>
#include <algorithm>
#include <Windows.h>

static std::string longest_path(const std::vector<std::string> &paths)
{
	if (paths.empty())
		return std::string();

	size_t length = paths[0].length();

	for (auto it = paths.cbegin(); it != paths.cend(); ++it)
	{
		if (it->length() < length)
		{
			length = it->length();
			continue;
		}

		const size_t l = std::mismatch(paths[0].cbegin(), paths[0].cend(), it->cbegin(), it->cend()).first - paths[0].cbegin();

		if (l < length)
			length = l;
	}

	return paths[0].substr(0, length);
}

blink::application::application() :
	_compiler_stdin(INVALID_HANDLE_VALUE),
	_compiler_stdout(INVALID_HANDLE_VALUE)
{
	_image_base = reinterpret_cast<BYTE *>(GetModuleHandle(nullptr));

	_symbols.insert({ "__ImageBase", _image_base });
}
blink::application::~application()
{
	CloseHandle(_compiler_stdin);
	CloseHandle(_compiler_stdout);
}

void blink::application::run()
{
	const auto headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(_image_base + reinterpret_cast<const IMAGE_DOS_HEADER *>(_image_base)->e_lfanew);

	{	print("Reading PE import directory ...");

		// Search import directory for additional symbols
		const IMAGE_DATA_DIRECTORY import_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		const auto import_directory_entries = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(_image_base + import_directory.VirtualAddress);

		for (unsigned int i = 0; import_directory_entries[i].FirstThunk != 0; i++)
		{
			const auto import_name_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(_image_base + import_directory_entries[i].Characteristics);
			const auto import_address_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(_image_base + import_directory_entries[i].FirstThunk);

			for (unsigned int k = 0; import_name_table[k].u1.AddressOfData != 0; k++)
			{
				const auto import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(_image_base + import_name_table[k].u1.AddressOfData);

				_symbols.insert({ import->Name, reinterpret_cast<void *>(import_address_table[k].u1.AddressOfData) });
			}
		}
	}

	{	print("Reading PE debug info directory ...");

		guid pdb_guid;
		std::string pdb_path;

		// Search debug directory for program debug database file name
		const IMAGE_DATA_DIRECTORY debug_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
		const auto debug_directory_entries = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY *>(_image_base + debug_directory.VirtualAddress);

		for (unsigned int i = 0; i < debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY); i++)
		{
			if (debug_directory_entries[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW)
				continue;

			struct RSDS_DEBUG_FORMAT
			{
				uint32_t signature;
				guid guid;
				uint32_t age;
				char path[1];
			};

			const auto data = reinterpret_cast<const RSDS_DEBUG_FORMAT *>(reinterpret_cast<const BYTE *>(_image_base + debug_directory_entries[i].AddressOfRawData));

			if (data->signature == 0x53445352) // RSDS
			{
				pdb_guid = data->guid;
				pdb_path = data->path;
				break;
			}
		}

		if (!pdb_path.empty())
		{
			print("  Found program debug database: " + pdb_path);

			pdb_reader pdb(pdb_path);

			// Check if the debug information actually matches the executable
			if (pdb.guid() == pdb_guid)
			{
				const auto pdb_symbols = pdb.symbols(_image_base);

				_symbols.insert(pdb_symbols.begin(), pdb_symbols.end());
				_source_files = pdb.sourcefiles();
			}
			else
			{
				print("  Error: Program debug database was created for a different executable file.");
				return;
			}
		}
		else
		{
			print("  Error: Could not find path to program debug database in executable image.");
			return;
		}
	}

	{	std::vector<std::string> cpp_files;

		for (const auto &path : _source_files)
		{
			// Let's add include directories for all source files and their parent folders
			for (size_t i = 0, offset = std::string::npos; i < 2; ++i, --offset)
			{
				offset = path.find_last_of('\\', offset);
				if (offset == std::string::npos)
					break;
				_include_dirs.insert(path.substr(0, offset));
			}

			if (path.find("c:\\program files") == std::string::npos &&
				path.find("f:\\dd") == std::string::npos &&
				path.find("d:\\agent\\_work") == std::string::npos &&
				path.rfind(".cpp") != std::string::npos)
			{
				print("  Found source file: " + path);

				cpp_files.push_back(path);
			}
		}

		_source_dir = longest_path(cpp_files);

		if (_source_dir.empty())
		{
			print("  Error: Could not determine project directory.");
			return;
		}
	}

	{	print("Starting compiler process ...");

		// Launch compiler process
		STARTUPINFO si = { sizeof(si) };
		si.dwFlags = STARTF_USESTDHANDLES;
		SECURITY_ATTRIBUTES sa = { sizeof(sa) };
		sa.bInheritHandle = TRUE;

		if (!CreatePipe(&si.hStdInput, &_compiler_stdin, &sa, 0))
			return;

		SetHandleInformation(_compiler_stdin, HANDLE_FLAG_INHERIT, FALSE);

		if (!CreatePipe(&_compiler_stdout, &si.hStdOutput, &sa, 0))
		{
			CloseHandle(si.hStdInput);
			return;
		}

		SetHandleInformation(_compiler_stdout, HANDLE_FLAG_INHERIT, FALSE);

		si.hStdError = si.hStdOutput;

		TCHAR cmdline[] = TEXT("cmd.exe /q /d");
		PROCESS_INFORMATION pi;

		if (!CreateProcess(nullptr, cmdline, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			CloseHandle(si.hStdInput);
			CloseHandle(si.hStdOutput);
			return;
		}

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(si.hStdInput);
		CloseHandle(si.hStdOutput);

		print("  Started process with PID " + std::to_string(pi.dwProcessId));

		// Set up compiler process environment variables
#if _M_IX86
		//const std::string command = "\"" + _build_tool + "\\..\\..\\vcvarsall.bat\" x86\n";
		const std::string command = "\"C:\\Program Files (x86)\\Microsoft Visual Studio 15.0\\VC\\Auxiliary\\Build\\vcvarsall.bat\" x86\n";
#endif
#if _M_AMD64
		//const std::string command = "\"" + _build_tool + "\\..\\..\\..\\vcvarsall.bat\" x86_amd64\n";
		const std::string command = "\"C:\\Program Files (x86)\\Microsoft Visual Studio 15.0\\VC\\Auxiliary\\Build\\vcvarsall.bat\" x86_amd64\n";
#endif
		DWORD size = 0;
		WriteFile(_compiler_stdin, command.c_str(), static_cast<DWORD>(command.size()), &size, nullptr);
	}

	print("Starting file system watcher for '" + _source_dir + "' ...");

	// Start file system watcher
	_watcher.reset(new file_watcher(_source_dir));

	bool executing = false;

	while (true)
	{
		Sleep(1);

		// Read compiler output messages
		DWORD size = 0;

		if (PeekNamedPipe(_compiler_stdout, nullptr, 0, nullptr, &size, nullptr) && size != 0)
		{
			std::string message(size, '\0');
			ReadFile(_compiler_stdout, const_cast<char *>(message.data()), size, &size, nullptr);

			for (size_t pos = 0, prev = 0; (pos = message.find('\n', prev)) != std::string::npos; prev = pos + 1)
			{
				const auto line = message.substr(prev, pos - prev);

				// Only print error information
				if (line.find("error") != std::string::npos || line.find("warning") != std::string::npos)
					print(line.c_str());
			}

			const size_t offset = message.find("compile complete");
			if (offset != std::string::npos)
			{
				const std::string exit_code = message.substr(offset + 17 /* strlen("compile complete ") */, message.find('\n', offset) - offset - 18);

				print("Finished compiling \"" + _compiled_module_file + "\" with code " + exit_code + ".");

				if (exit_code != "0") // Do not link if compilation was not successful
					_compiled_module_file.clear();

				executing = false;
			}
		}

		if (executing)
			continue;

		// Load compiled modules
		if (!_compiled_module_file.empty())
		{
			link(_compiled_module_file);

			_compiled_module_file.clear();
		}

		// Check for source modifications and recompile on changes
		std::vector<std::string> files;

		if (_watcher->check(files))
		{
			for (const auto &path : files)
			{
				if (path.substr(path.find_last_of('.') + 1) != "cpp")
					continue;

				executing = true;
				_compiled_module_file = path.substr(0, path.find_last_of('.')) + ".obj";

				print("Detected modification to: " + path);

				// Build compiler command line
				std::string cmdline = "cl.exe "
					"/c " // Compile only, do not link
					"/nologo " // Suppress copyright message
					"/Z7 " // Enable COFF debug information (required for symbol parsing in blink_linker.cpp!)
					"/MDd " // Link with 'MSVCRTD.lib'
					"/Od " // Disable optimizations
					"/EHsc " // Enable C++ exceptions
					"/std:c++latest " // C++ standard version
					"/Zc:wchar_t /Zc:forScope /Zc:inline"; // C++ language conformance
				for (const auto &define : _defines)
					cmdline += " /D \"" + define + "\"";
				for (const auto &include_path : _include_dirs)
					cmdline += " /I \"" + include_path + "\"";
				cmdline += " /Fo\"" + _compiled_module_file + "\""; // Output object file
				cmdline += " \"" + path + "\""; // Input source code file

				cmdline += "\necho compile complete %errorlevel%\n"; // Message used to confirm that compile finished in message loop above

				// Execute compiler command line
				WriteFile(_compiler_stdin, cmdline.c_str(), static_cast<DWORD>(cmdline.size()), &size, nullptr);
				break;
			}
		}
	}
}
