/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

namespace blink
{
	class file_watcher
	{
	public:
		explicit file_watcher(const std::string &path);
		~file_watcher();

		bool check(std::vector<std::string> &modified_file_paths);

	private:
		std::string _path;
		std::unique_ptr<unsigned char[]> _buffer;
		void *_handle, *_completion_handle;
	};
}
