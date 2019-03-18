/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "blink.hpp"
#include "pdb_reader.hpp"
#include "scoped_handle.hpp"
#include <string>
#include <algorithm>
#include <unordered_map>
#include <Windows.h>

static std::filesystem::path common_path(const std::vector<std::filesystem::path> &paths)
{
	if (paths.empty())
		return std::filesystem::path();

	std::filesystem::path all_common_path = paths[0].parent_path();

	for (auto it = paths.begin() + 1; it != paths.end(); ++it) {
		std::filesystem::path common_path;
		std::filesystem::path file_directory = it->parent_path();
		for (auto it2 = file_directory.begin(), it3 = all_common_path.begin(); it2 != file_directory.end() && it3 != all_common_path.end() && *it2 == *it3; ++it2, ++it3) {
			common_path /= *it2;
		}
		all_common_path = common_path;
	}

	return all_common_path;
}

blink::application::application()
{
	_image_base = reinterpret_cast<BYTE *>(GetModuleHandle(nullptr));

	_symbols.insert({ "__ImageBase", _image_base });
}

void blink::application::run()
{
	DWORD size = 0;

	const auto headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(_image_base + reinterpret_cast<const IMAGE_DOS_HEADER *>(_image_base)->e_lfanew);

	{	print("Reading PE import directory ...");

		// Search import directory for additional symbols
		const IMAGE_DATA_DIRECTORY import_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		const auto import_directory_entries = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(_image_base + import_directory.VirtualAddress);

		for (unsigned int i = 0; import_directory_entries[i].FirstThunk != 0; i++)
		{
			const auto name = reinterpret_cast<const char *>(_image_base + import_directory_entries[i].Name);
			const auto import_name_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(_image_base + import_directory_entries[i].Characteristics);
			const auto import_address_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(_image_base + import_directory_entries[i].FirstThunk);

			for (unsigned int k = 0; import_name_table[k].u1.AddressOfData != 0; k++)
			{
				const char *import_name = nullptr;

				// We need to figure out the name of symbols imported by ordinal by going through the export table of the target module
				if (IMAGE_SNAP_BY_ORDINAL(import_name_table[k].u1.Ordinal))
				{
					// The module should have already been loaded by Windows when the application was launched, so just get its handle here
					const auto target_base = reinterpret_cast<const BYTE *>(GetModuleHandleA(name));
					if (target_base == nullptr)
						continue; // Bail out if that is not the case to be safe

					const auto target_headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(target_base + reinterpret_cast<const IMAGE_DOS_HEADER *>(target_base)->e_lfanew);
					const auto export_directory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(target_base + target_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
					const auto export_name_strings = reinterpret_cast<const DWORD *>(target_base + export_directory->AddressOfNames);
					const auto export_name_ordinals = reinterpret_cast<const WORD *>(target_base + export_directory->AddressOfNameOrdinals);

					const auto ordinal = std::find(export_name_ordinals, export_name_ordinals + export_directory->NumberOfNames, IMAGE_ORDINAL(import_name_table[k].u1.Ordinal));
					if (ordinal != export_name_ordinals + export_directory->NumberOfNames)
						import_name = reinterpret_cast<const char *>(target_base + export_name_strings[std::distance(export_name_ordinals, ordinal)]);
					else
						continue; // Ignore ordinal imports for which the name could not be resolved
				}
				else
				{
					import_name = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(_image_base + import_name_table[k].u1.AddressOfData)->Name;
				}

				_symbols.insert({ import_name, reinterpret_cast<void *>(import_address_table[k].u1.AddressOfData) });
			}
		}
	}

	{	print("Reading PE debug info directory ...");

		struct RSDS_DEBUG_FORMAT
		{
			uint32_t signature;
			guid guid;
			uint32_t age;
			char path[1];
		} const *debug_data = nullptr;

		// Search debug directory for program debug database file name
		const IMAGE_DATA_DIRECTORY debug_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
		const auto debug_directory_entries = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY *>(_image_base + debug_directory.VirtualAddress);

		for (unsigned int i = 0; i < debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY); i++)
		{
			if (debug_directory_entries[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW)
			{
				debug_data = reinterpret_cast<const RSDS_DEBUG_FORMAT *>(reinterpret_cast<const BYTE *>(_image_base + debug_directory_entries[i].AddressOfRawData));

				if (debug_data->signature == 0x53445352) // RSDS
					break;
			}
		}

		if (debug_data != nullptr)
		{
			print("  Found program debug database: " + std::string(debug_data->path));

			pdb_reader pdb(debug_data->path);

			// Check if the debug information actually matches the executable
			if (pdb.guid() == debug_data->guid)
			{
				// The linker working directory should equal the project root directory
				std::string linker_cmd;
				pdb.read_link_info(_source_dir, linker_cmd);

				pdb.read_symbol_table(_image_base, _symbols);
				pdb.read_object_files(_object_files);
				pdb.read_source_files(_source_files);

				std::vector<std::filesystem::path> cpp_files;

				for (size_t i = 0; i < _object_files.size(); ++i)
				{
					if (std::error_code ec; _object_files[i].extension() != ".obj" || !std::filesystem::exists(_object_files[i], ec))
						continue;

					const auto it = std::find_if(_source_files[i].begin(), _source_files[i].end(),
						[](const auto &path) { const auto ext = path.extension(); return ext == ".c" || ext == ".cpp" || ext == ".cxx"; });

					if (it != _source_files[i].end())
					{
						print("  Found source file: " + it->string());

						cpp_files.push_back(*it);
					}
				}

				// The linker is invoked in solution directory, which may be out of source directory. Use source common path instead.
				_source_dir = common_path(cpp_files);
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

	if (_source_dir.empty())
	{
		print("  Error: Could not determine project directory. Make sure all source code files are on the same drive.");
		return;
	}

	scoped_handle compiler_stdin, compiler_stdout;

	{	print("Starting compiler process ...");

		// Launch compiler process
		STARTUPINFO si = { sizeof(si) };
		si.dwFlags = STARTF_USESTDHANDLES;
		SECURITY_ATTRIBUTES sa = { sizeof(sa) };
		sa.bInheritHandle = TRUE;

		if (!CreatePipe(&si.hStdInput, &compiler_stdin, &sa, 0))
		{
			print("  Error: Could not create input communication pipe.");
			return;
		}

		SetHandleInformation(compiler_stdin, HANDLE_FLAG_INHERIT, FALSE);

		if (!CreatePipe(&compiler_stdout, &si.hStdOutput, &sa, 0))
		{
			print("  Error: Could not create output communication pipe.");

			CloseHandle(si.hStdInput);
			return;
		}

		SetHandleInformation(compiler_stdout, HANDLE_FLAG_INHERIT, FALSE);

		si.hStdError = si.hStdOutput;

		TCHAR cmdline[] = TEXT("cmd.exe /q /d /k @echo off");
		PROCESS_INFORMATION pi;

		if (!CreateProcess(nullptr, cmdline, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			print("  Error: Could not create process.");

			CloseHandle(si.hStdInput);
			CloseHandle(si.hStdOutput);
			return;
		}

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(si.hStdInput);
		CloseHandle(si.hStdOutput);

		print("  Started process with PID " + std::to_string(pi.dwProcessId));
	}

	print("Starting file system watcher for '" + _source_dir.string() + "' ...");

	// Open handle to the common source code directory
	const scoped_handle watcher_handle = CreateFileW(_source_dir.native().c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

	if (watcher_handle == INVALID_HANDLE_VALUE)
	{
		print("  Error: Could not open directory handle.");
		return;
	}

	BYTE watcher_buffer[4096];

	// Check for modifications to any of the source code files
	while (ReadDirectoryChangesW(watcher_handle, watcher_buffer, sizeof(watcher_buffer), TRUE, FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME, &size, nullptr, nullptr))
	{
		bool first_notification = true;

		// Iterate over all notification items
		for (auto info = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(watcher_buffer); first_notification || info->NextEntryOffset != 0;
			first_notification = false, info = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(reinterpret_cast<BYTE *>(info) + info->NextEntryOffset))
		{
			std::filesystem::path source_file =
				_source_dir / std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR));

			// Ignore changes to files that are not C++ source files
			const std::filesystem::path ext = source_file.extension();
			const bool is_cpp_file = ext == ".c" || ext == ".cpp" || ext == ".cxx";
			const bool is_hpp_file = ext == ".h" || ext == ".hpp" || ext == ".hxx";
			if (!is_cpp_file && !is_hpp_file)
				continue;

			// Ignore duplicated notifications by comparing times and skipping any changes that are not older than 3 seconds
			if (const auto current_time = GetTickCount(); _last_modifications[source_file.string()] + 3000 > current_time)
				continue;
			else
				_last_modifications[source_file.string()] = current_time;

			print("Detected modification to: " + source_file.string());

			// Build compiler command line
			std::vector<std::pair<std::string, std::filesystem::path>> cmd_lines;
			if (!build_compile_command_lines(source_file, is_hpp_file, cmd_lines))
				continue; // Skip this file modification if something went wrong or the source file is an unreferenced header file

			for (auto &cmd_line : cmd_lines)
			{
				// Append special completion message
				cmd_line.first += "\necho Finished compiling \"" + cmd_line.second.string() + "\" with code %errorlevel%.\n"; // Message used to confirm that compile finished in message loop above

				// Execute compiler command line
				WriteFile(compiler_stdin, cmd_line.first.c_str(), static_cast<DWORD>(cmd_line.first.size()), &size, nullptr);

				// Read and react to compiler output messages
				while (WaitForSingleObject(compiler_stdout, INFINITE) == WAIT_OBJECT_0 && PeekNamedPipe(compiler_stdout, nullptr, 0, nullptr, &size, nullptr))
				{
					std::string message(size, '\0');
					ReadFile(compiler_stdout, message.data(), size, &size, nullptr);

					for (size_t offset = 0, next; (next = message.find('\n', offset)) != std::string::npos; offset = next + 1)
						print(message.data() + offset, next - offset + 1);

					// Listen for special completion message
					if (const size_t offset = message.find(" with code "); offset != std::string::npos)
					{
						// Only load the compiled module if compilation was successful
						if (const long exit_code = strtol(message.data() + offset + 11, nullptr, 10); exit_code == 0)
							link(cmd_line.second);
						break;
					}
				}

				// The OBJ file is not needed anymore.
				DeleteFileW(cmd_line.second.c_str());
			}
		}
	}
}

bool blink::application::build_compile_command_lines(const std::filesystem::path &source_file, bool is_header_file, std::vector<std::pair<std::string, std::filesystem::path>> &cmd_lines) const
{
	Sleep(100); // Prevent file system error in the next few code lines, TODO: figure out what causes this

	// Check if this source file already exists in the application in which case we can read some information from the original object file
	for (size_t i = 0; i < _source_files.size(); ++i)
	{
		const auto &module_files = _source_files[i];
		if (std::find_if(module_files.begin(), module_files.end(), [&source_file](const auto &file) {
				std::error_code ec; return std::filesystem::equivalent(source_file, file, ec);
			}) == module_files.end())
			continue; // Module does not contain this source file, continue to the next

		// This is a module that references the source file, so add a command line to recompile it
		auto &cmd_line = cmd_lines.emplace_back();
		cmd_line.second = source_file;

		if (is_header_file) // Need to find the source file for this module if compiling a header file
			if (const auto it = std::find_if(module_files.begin(), module_files.end(), [](const auto &file) {
					const auto ext = file.extension(); return ext == ".c" || ext == ".cpp" || ext == ".cxx";
				}); it != module_files.end())
				cmd_line.second = *it;
			else // Expect a module to contain a single C or C++ source file
				return false;

		stream_reader stream;
		{
			// Read original object file
			const scoped_handle file = CreateFileW(_object_files[i].native().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
			if (file == INVALID_HANDLE_VALUE)
				return false;

			IMAGE_FILE_HEADER header;
			if (DWORD read; !ReadFile(file, &header, sizeof(header), &read, nullptr))
				return false;
			std::vector<IMAGE_SECTION_HEADER> sections(header.NumberOfSections);
			if (DWORD read; !ReadFile(file, sections.data(), header.NumberOfSections * sizeof(IMAGE_SECTION_HEADER), &read, nullptr))
				return false;

			// Find first debug symbol section and read it
			const auto section = std::find_if(sections.begin(), sections.end(), [](const auto &s) {
				return strcmp(reinterpret_cast<const char(&)[]>(s.Name), ".debug$S") == 0; });
			std::vector<char> debug_data(section->SizeOfRawData);
			SetFilePointer(file, section->PointerToRawData, nullptr, FILE_BEGIN);
			if (DWORD read; !ReadFile(file, debug_data.data(), section->SizeOfRawData, &read, nullptr))
				return false;

			stream = stream_reader(std::move(debug_data));
		}

		// Skip header in front of CodeView records (version, ...)
		stream.skip(4 * 3);

		parse_code_view_records(stream, [&](uint16_t tag) {
			if (tag != 0x113d) // S_ENVBLOCK
				return; // Skip all records that are not about the compiler environment
			stream.skip(1);
			while (stream.tell() < stream.size() && *stream.data() != '\0')
			{
				const auto key = stream.read_string();
				const std::string value(stream.read_string());

				if (key == "cwd")
					cmd_line.first += "cd /D \"" + value + "\"\n";
				else if (key == "cl") // Add compiler directories to path, so that 'mspdbcore.dll' is found
					cmd_line.first += "set PATH=%PATH%;" + value + "\\..\\..\\x86;" + value + "\\..\\..\\x64\n\"" + value + "\" ";
				else if (key == "cmd")
					cmd_line.first += value;
			}
		});
	}

	if (cmd_lines.empty())
	{
		// Ignore changes to header files that aren't referenced by the application
		if (is_header_file)
		{
			print("Warning: Ignoring unreferenced header file " + source_file.string() + ".\n");
			return false;
		}

		// Fall back to a default command-line if unable to find one
		cmd_lines.emplace_back(
			"cl.exe "
			"/nologo " // Suppress copyright message
			"/Z7 " // Enable COFF debug information
			"/MDd " // Link with 'MSVCRTD.lib'
			"/Od " // Disable optimizations
			"/EHsc " // Enable C++ exceptions
			"/std:c++latest " // C++ standard version
			"/Zc:wchar_t /Zc:forScope /Zc:inline ", // C++ language conformance
			source_file);
	}

	for (auto &cmd_line : cmd_lines)
	{
		// Make sure to only compile and not link too
		cmd_line.first += " /c ";

		// Remove some arguments from the command-line since they are set to different values below
		const auto remove_arg = [&args = cmd_line.first](std::string arg) {
			for (unsigned int k = 0; k < 2; ++k)
				if (size_t offset = args.find("-/"[k] + arg); offset != std::string::npos)
				{
					if (args[offset + 1 + arg.size()] != '\"')
						args.erase(offset, args.find(' ', offset) - offset);
					else
						args.erase(offset, args.find('\"', offset + 2 + arg.size()) + 2 - offset);
					break;
				}
		};

		remove_arg("Fo");
		remove_arg("Fd"); // The program debug database is currently in use by the running application, so cannot write to it
		remove_arg("ZI"); // Do not create a program debug database, since all required debug information can be stored in the object file instead
		remove_arg("Yu"); // Disable pre-compiled headers, since the data is not accessible here
		remove_arg("Yc");
		remove_arg("JMC");

		// Append input source file to command-line
		cmd_line.first += '\"' + cmd_line.second.string() + '\"';

		// Always write to a separate object file since the original one may be in user by a debugger
		cmd_line.second.replace_extension("temp.obj");

		// Append output object file to command-line
		cmd_line.first += " /Fo\"" + cmd_line.second.string() + '\"';
	}

	return true;
}
