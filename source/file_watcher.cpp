/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "file_watcher.hpp"
#include <Windows.h>

static const DWORD buffer_size = sizeof(FILE_NOTIFY_INFORMATION) + MAX_PATH * sizeof(WCHAR);

blink::file_watcher::file_watcher(const std::string &path) : _path(path), _buffer(new unsigned char[buffer_size])
{
	_handle = CreateFileA(path.c_str(), FILE_LIST_DIRECTORY, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, nullptr);
	_completion_handle = CreateIoCompletionPort(_handle, nullptr, reinterpret_cast<ULONG_PTR>(_handle), 1);

	OVERLAPPED overlapped = {};
	ReadDirectoryChangesW(_handle, _buffer.get(), buffer_size, TRUE, FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME, nullptr, &overlapped, nullptr);
}
blink::file_watcher::~file_watcher()
{
	CancelIo(_handle);

	CloseHandle(_handle);
	CloseHandle(_completion_handle);
}

bool blink::file_watcher::check(std::vector<std::string> &modifications)
{
	DWORD transferred;
	ULONG_PTR key;
	OVERLAPPED *overlapped;

	if (!GetQueuedCompletionStatus(_completion_handle, &transferred, &key, &overlapped, 0))
		return false;

	auto record = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(_buffer.get());

	while (true)
	{
		record->FileNameLength /= sizeof(WCHAR);

		std::string filename(MAX_PATH + 1, 0);
		filename.resize(WideCharToMultiByte(CP_UTF8, 0, record->FileName, record->FileNameLength, const_cast<char *>(filename.data()), MAX_PATH, nullptr, nullptr));
		filename = _path + '\\' + filename;

		modifications.push_back(std::move(filename));

		if (record->NextEntryOffset == 0)
			break;

		record = reinterpret_cast<FILE_NOTIFY_INFORMATION *>(reinterpret_cast<BYTE *>(record) + record->NextEntryOffset);
	}

	// Avoid duplicated notifications
	// TODO: Find a proper solution
	Sleep(100);

	overlapped->hEvent = nullptr;

	ReadDirectoryChangesW(_handle, _buffer.get(), buffer_size, TRUE, FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME, nullptr, overlapped, nullptr);

	return true;
}
