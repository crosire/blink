#include "filewatcher.hpp"

#include <Windows.h>

const DWORD buffer_size = sizeof(FILE_NOTIFY_INFORMATION) + MAX_PATH * sizeof(WCHAR);

filewatcher::filewatcher(const std::string &path) : _path(path), _buffer(new unsigned char[buffer_size])
{
	_handle = CreateFileA(path.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
	_completion_handle = CreateIoCompletionPort(_handle, nullptr, reinterpret_cast<ULONG_PTR>(_handle), 1);

	OVERLAPPED overlapped = { };
	ReadDirectoryChangesW(_handle, _buffer.get(), buffer_size, TRUE, FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME, nullptr, &overlapped, nullptr);
}
filewatcher::~filewatcher()
{
	CancelIo(_handle);

	CloseHandle(_handle);
	CloseHandle(_completion_handle);
}

bool filewatcher::check(std::vector<std::string> &modifications)
{
	DWORD transferred;
	ULONG_PTR key;
	OVERLAPPED *overlapped;

	if (!GetQueuedCompletionStatus(_completion_handle, &transferred, &key, &overlapped, 0))
	{
		return false;
	}

	const DWORD time = GetTickCount();

	auto record = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(_buffer.get());

	while (true)
	{
		record->FileNameLength /= sizeof(WCHAR);

		std::string filename(MAX_PATH, 0);
		filename.resize(WideCharToMultiByte(CP_UTF8, 0, record->FileName, record->FileNameLength, const_cast<char *>(filename.data()), static_cast<int>(filename.size()), nullptr, nullptr));
		filename = _path + '\\' + filename;

		if (_file_times[filename] < time - 5000)
		{
			_file_times[filename] = time;

			modifications.push_back(std::move(filename));
		}

		if (record->NextEntryOffset == 0)
		{
			break;
		}

		record = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(reinterpret_cast<BYTE *>(record) + record->NextEntryOffset);
	}

	overlapped->hEvent = nullptr;

	ReadDirectoryChangesW(_handle, _buffer.get(), buffer_size, TRUE, FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME, nullptr, overlapped, nullptr);

	return true;
}
