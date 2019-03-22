/**
 * Copyright (C) 2019 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "coff_reader.hpp"

scoped_handle open_coff_file(const std::filesystem::path &path, COFF_HEADER &header)
{
	scoped_handle file = CreateFileW(path.native().c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	if (INVALID_HANDLE_VALUE == file)
		return INVALID_HANDLE_VALUE;

	// Read COFF header from input file and check that it is of a valid format
	if (DWORD read; !ReadFile(file, &header, sizeof(header), &read, nullptr))
		return INVALID_HANDLE_VALUE;

	// Need to adjust file position if this is not an extended COFF, since the normal header is smaller
	if (!header.is_extended())
		SetFilePointer(file, sizeof(header.obj), nullptr, FILE_BEGIN);

	return std::move(file);
}
