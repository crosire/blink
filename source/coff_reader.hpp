/**
 * Copyright (C) 2019 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#pragma once

#include <filesystem>
#include "scoped_handle.hpp"

union COFF_HEADER
{
	bool is_extended() const {
		return bigobj.Sig1 == 0x0000 && bigobj.Sig2 == 0xFFFF;
	}

	IMAGE_FILE_HEADER obj;
	ANON_OBJECT_HEADER_BIGOBJ bigobj;
};

scoped_handle open_coff_file(const std::filesystem::path &path, COFF_HEADER &header);
