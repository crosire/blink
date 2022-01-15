/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#pragma once

#include <Windows.h>

struct scoped_handle
{
	HANDLE handle;

	scoped_handle() :
		handle(INVALID_HANDLE_VALUE) {}
	scoped_handle(HANDLE handle) :
		handle(handle) {}
	scoped_handle(scoped_handle &&other) :
		handle(other.handle) { other.handle = NULL; }
	~scoped_handle() { if (handle != NULL && handle != INVALID_HANDLE_VALUE) CloseHandle(handle); }

	operator HANDLE() const { return handle; }

	void reset(const HANDLE p) {
		if (handle != p) {
			if (handle != NULL && handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
			handle = p;
		}
	}

	HANDLE *operator&() { return &handle; }
	const HANDLE *operator&() const { return &handle; }
};
