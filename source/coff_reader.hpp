/**
 * Copyright (C) 2019 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#pragma once

#include <filesystem>
#include "scoped_handle.hpp"

union COFF_HEADER
{
	constexpr static const uint8_t bigobj_classid[16] = {
		0xc7, 0xa1, 0xba, 0xd1, 0xee, 0xba, 0xa9, 0x4b,
		0xaf, 0x20, 0xfa, 0xf6, 0x6a, 0xa4, 0xdc, 0xb8,
	};

	//This is actually a 16byte UUID
	static_assert(sizeof(bigobj_classid) == sizeof(CLSID));

	bool is_extended() const {
		return bigobj.Sig1 == 0x0000 && bigobj.Sig2 == 0xFFFF && memcmp(&bigobj.ClassID, bigobj_classid, sizeof(CLSID)) == 0 ;
	}

	IMAGE_FILE_HEADER obj;
	ANON_OBJECT_HEADER_BIGOBJ bigobj;
};

scoped_handle open_coff_file(const std::filesystem::path &path, COFF_HEADER &header);
