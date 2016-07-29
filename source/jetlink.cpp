#include "jetlink.hpp"
#include "jetlink_reader_pdb.hpp"
#include "filewatcher.hpp"

#include <string>
#include <atomic>
#include <unordered_map>
#include <algorithm>
#include <Windows.h>

namespace jetlink
{
	std::string longest_path(const std::vector<std::string> &dirs, char separator)
	{
		std::vector<std::string>::const_iterator vsi = dirs.begin();
		ptrdiff_t maxCharactersCommon = vsi->length();
		std::string compareString = *vsi;
		for (vsi = dirs.begin() + 1; vsi != dirs.end(); vsi++)
		{
			std::pair<std::string::const_iterator, std::string::const_iterator> p =
				std::mismatch(compareString.begin(), compareString.end(), vsi->begin());
			if ((p.first - compareString.begin()) < maxCharactersCommon)
				maxCharactersCommon = p.first - compareString.begin();
		}
		std::string::size_type found = compareString.rfind(separator, maxCharactersCommon);
		return compareString.substr(0, found);
	}

	application::application() : _initialized(false), _executing(false), _compiler_stdin(INVALID_HANDLE_VALUE), _compiler_stdout(INVALID_HANDLE_VALUE)
	{
		_imagebase = reinterpret_cast<BYTE *>(GetModuleHandle(nullptr));
		const auto headers = reinterpret_cast<const IMAGE_NT_HEADERS *>(_imagebase + reinterpret_cast<const IMAGE_DOS_HEADER *>(_imagebase)->e_lfanew);

		print("Reading PE import directory ...\n");

		#pragma region // Search import directory for additional symbols
		const IMAGE_DATA_DIRECTORY import_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
		const auto import_directory_entries = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR *>(_imagebase + import_directory.VirtualAddress);

		for (unsigned int i = 0; import_directory_entries[i].FirstThunk != 0; i++)
		{
			const auto import_name_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(_imagebase + import_directory_entries[i].Characteristics);
			const auto import_address_table = reinterpret_cast<const IMAGE_THUNK_DATA *>(_imagebase + import_directory_entries[i].FirstThunk);

			for (unsigned int k = 0; import_name_table[k].u1.AddressOfData != 0; k++)
			{
				const auto import = reinterpret_cast<const IMAGE_IMPORT_BY_NAME *>(_imagebase + import_name_table[k].u1.AddressOfData);

				_symbols.insert({ import->Name, reinterpret_cast<void *>(import_address_table[k].u1.AddressOfData) });
			}
		}
		#pragma endregion

		print("Reading PE debug info directory ...\n");

		#pragma region // Search debug directory for program debug database file name
		guid pdb_guid;
		std::string pdb_path;
		const IMAGE_DATA_DIRECTORY debug_directory = headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
		const auto debug_directory_entries = reinterpret_cast<const IMAGE_DEBUG_DIRECTORY *>(_imagebase + debug_directory.VirtualAddress);

		for (unsigned int i = 0; i < debug_directory.Size / sizeof(IMAGE_DEBUG_DIRECTORY); i++)
		{
			if (debug_directory_entries[i].Type != IMAGE_DEBUG_TYPE_CODEVIEW)
			{
				continue;
			}

			const auto data = reinterpret_cast<const BYTE *>(_imagebase + debug_directory_entries[i].AddressOfRawData);

			if (*reinterpret_cast<const DWORD *>(data) == 0x53445352)
			{
				pdb_guid = *reinterpret_cast<const guid *>(data + 4);
				pdb_path = reinterpret_cast<const char *>(data + 24);
				break;
			}
		}
		#pragma endregion

		if (!pdb_path.empty())
		{
			print("  Found program debug database: " + pdb_path + '\n');

			pdb_reader pdb(pdb_path);

			// Check if the debug information actually matches the executable
			if (pdb.guid() == pdb_guid)
			{
				for (const auto &symbol : pdb.symbols())
				{
					_symbols.insert({ symbol.first, _imagebase + symbol.second });
				}

				_sourcefiles = pdb.sourcefiles();
			}
			else
			{
				print("  Error: Program debug database was created for a different executable file.\n");
				return;
			}
		}
		else
		{
			print("  Error: Could not find path to program debug database in executable image.\n");
			return;
		}

		_symbols.insert({ "__ImageBase", _imagebase });

		for (const auto &path : _sourcefiles)
		{
			print("  Found source file: " + path + '\n');
		}

		_source_dir = longest_path(_sourcefiles, '\\');

		print("Starting compiler process ...\n");

		const char msvcversion[] = "12.0"; // TODO: Read this from PDB
		#pragma region // Search for Visual Studio installation path
		HKEY key = nullptr;
		DWORD size = MAX_PATH;
		char msvcpath[MAX_PATH + 1];

		if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\VisualStudio\\SxS\\VC7", 0, KEY_READ | KEY_WOW64_32KEY, &key) || RegQueryValueEx(key, msvcversion, nullptr, nullptr, reinterpret_cast<BYTE *>(msvcpath), &size) | RegCloseKey(key))
		{
			return;
		}
		#pragma endregion

		print("  Found Visual Studio: " + std::string(msvcpath) + '\n');

		#pragma region // Launch compiler process
		STARTUPINFO si = { sizeof(si) };
		si.dwFlags = STARTF_USESTDHANDLES;
		SECURITY_ATTRIBUTES sa = { sizeof(sa) };
		sa.bInheritHandle = TRUE;

		if (!CreatePipe(&si.hStdInput, &_compiler_stdin, &sa, 0))
		{
			return;
		}

		SetHandleInformation(_compiler_stdin, HANDLE_FLAG_INHERIT, FALSE);

		if (!CreatePipe(&_compiler_stdout, &si.hStdOutput, &sa, 0))
		{
			CloseHandle(si.hStdInput);
			return;
		}

		SetHandleInformation(_compiler_stdout, HANDLE_FLAG_INHERIT, FALSE);

		si.hStdError = si.hStdOutput;

		char cmdline[] = "cmd.exe /q /d";
		PROCESS_INFORMATION pi;

		if (!CreateProcessA(nullptr, cmdline, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi))
		{
			CloseHandle(si.hStdInput);
			CloseHandle(si.hStdOutput);
			return;
		}

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		CloseHandle(si.hStdInput);
		CloseHandle(si.hStdOutput);
		#pragma endregion

		print("  Started process with PID " + std::to_string(pi.dwProcessId) + '\n');

		#pragma region // Set up compiler process environment variables
#if _M_IX86
		const std::string command = "\"" + std::string(msvcpath) + "vcvarsall.bat\" x86\n";
#endif
#if _M_AMD64
		const std::string command = "\"" + std::string(msvcpath) + "vcvarsall.bat\" x86_amd64\n";
#endif
		WriteFile(_compiler_stdin, command.c_str(), static_cast<DWORD>(command.size()), &size, nullptr);
		#pragma endregion

		print("Starting file system watcher for '" + _source_dir + "' ...\n");

		// Start file system watcher
		_filewatcher.reset(new filewatcher(_source_dir));

		_initialized = true;
	}
	application::~application()
	{
		CloseHandle(_compiler_stdin);
		CloseHandle(_compiler_stdout);
	}

	void application::run()
	{
		if (!_initialized)
		{
			return;
		}

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
					const auto line = message.substr(prev, pos - prev + 1);

					if (line.find("error") != std::string::npos || line.find("warning") != std::string::npos)
					{
						print(line.c_str());
					}
				}

				if (message.find("compile complete") != std::string::npos)
				{
					print("Finished compiling.\n");

					_executing = false;
				}
			}

			if (_executing)
			{
				continue;
			}

			// Load compiled modules
			if (!_compiled_module_file.empty())
			{
				link(_compiled_module_file);

				_compiled_module_file.clear();
			}

			// Check for source modifications and recompile on changes
			std::vector<std::string> files;

			if (_filewatcher->check(files))
			{
				for (const auto &path : files)
				{
					if (path.substr(path.find_last_of('.') + 1) != "cpp")
					{
						continue;
					}

					_executing = true;
					_compiled_module_file = path.substr(0, path.find_last_of('.')) + ".obj";

					std::vector<std::string> includes;
					includes.push_back(_source_dir);

					print("Detected modification to: " + path + '\n');

					// Build compiler command line
					std::string cmdline = "cl /c /nologo /GS /W3 /Zc:wchar_t /Z7 /Od /fp:precise /errorReport:prompt /WX- /Zc:forScope /Gd /MDd /EHsc";
					cmdline += " /Fo\"" + _compiled_module_file + "\"";
					cmdline += " \"" + path + "\"";

					for (const auto &include_path : includes)
					{
						cmdline += " /I \"" + include_path + "\"";
					}

					cmdline += "\necho compile complete\n";

					// Execute compiler command line
					WriteFile(_compiler_stdin, cmdline.c_str(), static_cast<DWORD>(cmdline.size()), &size, nullptr);
					break;
				}
			}
		}
	}
}
