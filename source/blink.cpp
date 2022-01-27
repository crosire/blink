/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "blink.hpp"
#include "coff_reader.hpp"
#include <string>
#include <algorithm>
#include <unordered_map>

static void add_unique_path(std::vector<std::filesystem::path> &paths, const std::filesystem::path &path)
{
	if (path.empty())
		return;

	if (std::find(paths.begin(), paths.end(), path) == paths.end()) {
		paths.push_back(path);
	}
}

static void common_paths(const std::vector<std::filesystem::path> &paths, std::vector<std::filesystem::path> &source_dirs)
{
	if (paths.empty())
		return;

	add_unique_path(source_dirs, paths[0].parent_path());

	for (auto path_it = paths.begin() + 1; path_it != paths.end(); ++path_it) {
		// only consider files that exist, ie: can be watched
		if (!std::filesystem::exists(*path_it)) {
			continue;
		}
		std::filesystem::path file_directory = path_it->parent_path();
		bool found_path = false;
		for (std::vector<std::filesystem::path>::iterator dir_it = source_dirs.begin(); dir_it != source_dirs.end(); ++dir_it) {
			auto source_dir = *dir_it;
			std::filesystem::path common_path;
			for (auto it2 = file_directory.begin(), it3 = source_dir.begin(); it2 != file_directory.end() && it3 != source_dir.end() && *it2 == *it3; ++it2, ++it3) {
				common_path /= *it2;
			}
			if (!common_path.empty()) {
				found_path = true;
				*dir_it = common_path;
			}
		}
		if (!found_path && !file_directory.empty()) {
			add_unique_path(source_dirs, file_directory);
		}
	}
}

blink::application::application()
{
	_image_base = reinterpret_cast<BYTE *>(GetModuleHandle(nullptr));

	_symbols.insert({ "__ImageBase", _image_base });
}

void blink::application::run(HANDLE blink_handle)
{
	std::vector<const BYTE *> dlls;

	{	print("Reading PE import directory ...");

		read_import_address_table(_image_base);
	}

	{	print("Reading PE debug info directory ...");

		if (!read_debug_info(_image_base))
		{
			print("  Error: Could not find path to matching program debug database in executable image.");
			return;
		}

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

		// The linker is invoked in solution directory, which may be out of source directory. Use source common paths instead.
		common_paths(cpp_files, _source_dirs);
	}

	if (_source_dirs.empty())
	{
		print("  Error: Could not determine source directories. Check your .pdb file for source files.");
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

	size_t dir_index = 0;
	std::vector<scoped_handle> dir_handles;
	std::vector<scoped_handle> event_handles;
	std::vector<notification_info> notification_infos;
	for (auto it = _source_dirs.begin(); it != _source_dirs.end(); ++it) {
		auto source_dir = *it;
		print("Starting file system watcher for '" + source_dir.string() + "' ...");

		dir_handles.emplace_back();
		event_handles.emplace_back();
		notification_infos.emplace_back();

		if (!set_watch(dir_index, dir_handles, event_handles, notification_infos))
			return;
		++dir_index;
	}

	DWORD size = 0;
	DWORD bytes_written = 0;
	while (PeekNamedPipe(compiler_stdout, nullptr, 0, nullptr, &size, nullptr) &&
		PeekNamedPipe(blink_handle, nullptr, 0, nullptr, &size, nullptr)  // while blink.exe is still running
	) {
		const DWORD wait_result = WaitForMultipleObjects(event_handles.size(), &event_handles[0], FALSE, 1000);
		if (wait_result == WAIT_FAILED)
			break;
		if (wait_result == WAIT_TIMEOUT)
			continue;
		dir_index = wait_result;
		DWORD bytes_transferred = 0;

		const BOOL overlapped_success = GetOverlappedResult(dir_handles[dir_index], &notification_infos[dir_index].overlapped,
			&bytes_transferred, TRUE);

		if (!overlapped_success) {
			print("  Error: GetOverlappedResult failed.");
			return;
		}

		bool first_notification = true;
		// Iterate over all notification items
		for (auto info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(notification_infos[dir_index].p_info.data()); first_notification || info->NextEntryOffset != 0;
			first_notification = false, info = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(reinterpret_cast<BYTE*>(info) + info->NextEntryOffset))
		{
			std::filesystem::path object_file, source_file =
				_source_dirs[dir_index] / std::wstring(info->FileName, info->FileNameLength / sizeof(WCHAR));

			// Ignore changes to files that are not C++ source files
			if (const auto ext = source_file.extension(); ext != ".c" && ext != ".cpp" && ext != ".cxx")
				continue;

			// Ignore duplicated notifications by comparing times and skipping any changes that are not older than 3 seconds
			if (const auto current_time = GetTickCount(); _last_modifications[source_file.string()] + 3000 > current_time)
				continue;
			else
				_last_modifications[source_file.string()] = current_time;

			print("Detected modification to: " + source_file.string());

			// Build compiler command line
			std::string cmdline = build_compile_command_line(source_file, object_file);

			// Append special completion message
			cmdline += "\necho Finished compiling \"" + object_file.string() + "\" with code %errorlevel%.\n"; // Message used to confirm that compile finished in message loop above

			// Execute compiler command line
			WriteFile(compiler_stdin, cmdline.c_str(), static_cast<DWORD>(cmdline.size()), &size, nullptr);

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
					{
						call_symbol("__blink_sync", source_file.string().c_str()); // Notify application that we want to link an object file
						const bool link_success = link(object_file);
						call_symbol("__blink_release", source_file.string().c_str(), link_success); // Notify application that we have finished work
					}
					break;
				}
			}

			// The OBJ file is not needed anymore.
			DeleteFileW(object_file.c_str());
		}
		if (!set_watch(dir_index, dir_handles, event_handles, notification_infos))
			return;
	}
}

bool blink::application::read_debug_info(const BYTE *image_base)
{
	struct RSDS_DEBUG_FORMAT
	{
		uint32_t signature;
		guid guid;
		uint32_t age;
		char path[1];
	} const *debug_data = nullptr;

	const auto headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(
		image_base + reinterpret_cast<const IMAGE_DOS_HEADER *>(image_base)->e_lfanew);

	// Search debug directory for program debug database file name
	const IMAGE_DATA_DIRECTORY &debug_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
	const auto debug_directory_entries = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY *>(
		image_base + debug_directory.VirtualAddress);

	for (unsigned int i = 0; i < debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY); ++i)
	{
		if (debug_directory_entries[i].Type == IMAGE_DEBUG_TYPE_CODEVIEW)
		{
			debug_data = reinterpret_cast<const RSDS_DEBUG_FORMAT *>(
				image_base + debug_directory_entries[i].AddressOfRawData);
			if (debug_data->signature == 0x53445352) // RSDS
				break;
		}
	}

	if (debug_data == nullptr)
		return false;

	pdb_reader pdb(debug_data->path);

	// Check if the debug information actually matches the executable
	if (pdb.guid() != debug_data->guid)
		return false;

	print("  Found program debug database: " + std::string(debug_data->path));

	// The linker working directory should equal the project root directory
	std::string linker_cmd;
	std::filesystem::path source_dir;
	pdb.read_link_info(source_dir, linker_cmd);
	if (!source_dir.empty()) {
		add_unique_path(_source_dirs, source_dir);
	}

	pdb.read_symbol_table(_image_base, _symbols);
	pdb.read_object_files(_object_files);
	pdb.read_source_files(_source_files, _source_file_map);

	return true;
}
void blink::application::read_import_address_table(const BYTE *image_base)
{
	const auto headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(
		_image_base + reinterpret_cast<const IMAGE_DOS_HEADER *>(_image_base)->e_lfanew);

	// Search import directory for additional symbols
	const IMAGE_DATA_DIRECTORY &import_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	const auto import_directory_entries = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(_image_base + import_directory.VirtualAddress);

	for (unsigned int i = 0; import_directory_entries[i].FirstThunk != 0; i++)
	{
		const auto name = reinterpret_cast<const char *>(_image_base + import_directory_entries[i].Name);
		const auto import_name_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(_image_base + import_directory_entries[i].Characteristics);
		const auto import_address_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(_image_base + import_directory_entries[i].FirstThunk);

		// The module should have already been loaded by Windows when the application was launched, so just get its handle here
		const auto target_base = reinterpret_cast<const BYTE *>(GetModuleHandleA(name));
		if (target_base == nullptr)
			continue; // Bail out if that is not the case to be safe

		for (unsigned int k = 0; import_name_table[k].u1.AddressOfData != 0; k++)
		{
			const char *import_name = nullptr;

			// We need to figure out the name of symbols imported by ordinal by going through the export table of the target module
			if (IMAGE_SNAP_BY_ORDINAL(import_name_table[k].u1.Ordinal))
			{
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

		read_debug_info(target_base);
	}
}

bool blink::application::set_watch(
	const size_t dir_index,
	std::vector<scoped_handle> &dir_handles,
	std::vector<scoped_handle> &event_handles,
	std::vector<notification_info> &notification_infos)
{
	dir_handles[dir_index].reset(CreateFileW(_source_dirs[dir_index].native().c_str(),
		GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr));
	if (dir_handles[dir_index] == INVALID_HANDLE_VALUE)
	{
		print("  Error: Could not open directory handle.");
		return false;
	}

	notification_infos[dir_index].overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	event_handles[dir_index].reset(notification_infos[dir_index].overlapped.hEvent);
	if (NULL == event_handles[dir_index])
	{
		print("  Error: CreateEvent failed.");
		return false;
	}

	DWORD size = 0;
	if (0 == ReadDirectoryChangesW(dir_handles[dir_index], reinterpret_cast<FILE_NOTIFY_INFORMATION*>(notification_infos[dir_index].p_info.data()),
		notification_infos[dir_index].p_info.size(), TRUE, FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME, &size, &(notification_infos[dir_index].overlapped), nullptr)) {
		print("  Error: ReadDirectoryChangesW failed.");
		return false;
	}
	return true;
}

std::string blink::application::build_compile_command_line(const std::filesystem::path &source_file, std::filesystem::path &object_file) const
{
	std::string cmdline;

	Sleep(100); // Prevent file system error in the next few code lines, TODO: figure out what causes this

	// Check if this source file already exists in the application in which case we can read some information from the original object file
	auto it = _source_file_map.find(source_file);
	if (it != _source_file_map.end())
	{
		object_file = _object_files[it->second.module];

		// Read original object file
		COFF_HEADER header;
		const scoped_handle file = open_coff_file(object_file, header);
		if (file != INVALID_HANDLE_VALUE)
		{
			DWORD read = header.is_extended() ? header.bigobj.NumberOfSections : header.obj.NumberOfSections;
			std::vector<IMAGE_SECTION_HEADER> sections(read);
			ReadFile(file, sections.data(), read * sizeof(IMAGE_SECTION_HEADER), &read, nullptr);

			// Find first debug symbol section and read it
			const auto section = std::find_if(sections.begin(), sections.end(), [](const auto &s) {
				return strcmp(reinterpret_cast<const char(&)[]>(s.Name), ".debug$S") == 0; });
			if (section != sections.end())
			{
				std::vector<char> debug_data(section->SizeOfRawData);
				SetFilePointer(file, section->PointerToRawData, nullptr, FILE_BEGIN);
				ReadFile(file, debug_data.data(), section->SizeOfRawData, &read, nullptr);

				// Skip header in front of CodeView records (version, ...)
				stream_reader stream(std::move(debug_data));
				stream.skip(4); // Skip 32-bit signature (this should be CV_SIGNATURE_C13, aka 4)

				while (stream.tell() < stream.size() && cmdline.empty())
				{
					// CV_DebugSSubsectionHeader_t
					const auto subsection_type = stream.read<uint32_t>();
					const auto subsection_length = stream.read<uint32_t>();
					if (subsection_type != 0xf1 /*DEBUG_S_SYMBOLS*/)
					{
						stream.skip(subsection_length);
						stream.align(4);
						continue;
					}

					parse_code_view_records(stream, subsection_length, [&](uint16_t tag) {
						if (tag != 0x113d) // S_ENVBLOCK
							return; // Skip all records that are not about the compiler environment
						stream.skip(1);
						while (stream.tell() < stream.size() && *stream.data() != '\0')
						{
							const auto key = stream.read_string();
							const std::string value(stream.read_string());

							if (key == "cwd")
								cmdline += "cd /D \"" + value + "\"\n";
							else if (key == "cl") // Add compiler directories to path, so that 'mspdbcore.dll' is found
								cmdline += "set PATH=%PATH%;" + value + "\\..\\..\\x86;" + value + "\\..\\..\\x64\n\"" + value + "\" ";
							else if (key == "cmd")
								cmdline += value;
						}
					});

					stream.align(4); // Subsection headers are 4-byte aligned
				}
			}
		}
	}

	// Fall back to default command-line if unable to extract it
	if (cmdline.empty())
	{
		cmdline = "cl.exe "
			"/nologo " // Suppress copyright message
			"/Z7 " // Enable COFF debug information
			"/MDd " // Link with 'MSVCRTD.lib'
			"/Od " // Disable optimizations
			"/EHsc " // Enable C++ exceptions
			"/std:c++latest " // C++ standard version
			"/Zc:wchar_t /Zc:forScope /Zc:inline "; // C++ language conformance
	}

	// Make sure to only compile and not link too
	cmdline += " /c ";

	// Remove some arguments from the command-line since they are set to different values below
	const auto remove_arg = [&cmdline](std::string arg) {
		for (unsigned int k = 0; k < 2; ++k)
			if (size_t offset = cmdline.find("-/"[k] + arg); offset != std::string::npos)
			{
				if (cmdline[offset + 1 + arg.size()] != '\"')
					cmdline.erase(offset, cmdline.find(' ', offset) - offset);
				else
					cmdline.erase(offset, cmdline.find('\"', offset + 2 + arg.size()) + 2 - offset);
				break;
			}
	};

	remove_arg("Fo");
	remove_arg("Fd"); // The program debug database is currently in use by the running application, so cannot write to it
	remove_arg("ZI"); // Do not create a program debug database, since all required debug information can be stored in the object file instead
	remove_arg("Yu"); // Disable pre-compiled headers, since the data is not accessible here
	remove_arg("Yc");
	remove_arg("JMC");

	// Always write to a separate object file since the original one may be in user by a debugger
	object_file = source_file; object_file.replace_extension("temp.obj");

	// Append input source file to command-line
	cmdline += '\"' + source_file.string() + '\"';

	// Append output object file to command-line
	cmdline += " /Fo\"" + object_file.string() + '\"';

	return cmdline;
}
