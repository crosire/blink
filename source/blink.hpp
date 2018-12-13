/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#pragma once

#include <memory>
#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>

void print(const char *message, size_t length);
inline void print(std::string message)
{
	message += '\n';
	print(message.data(), message.size());
}

namespace blink
{
	class application
	{
	public:
		application();
		~application();

		void run();
		bool link(const std::string &path);

	private:
		uint8_t *_image_base = nullptr;
		std::vector<std::string> _defines;
		std::vector<std::string> _source_files;
		std::vector<std::string> _source_files_to_compile;
		std::unordered_set<std::string> _include_dirs;
		std::unordered_map<std::string, void *> _symbols;
		std::unique_ptr<class file_watcher> _watcher;
		void *_compiler_stdin, *_compiler_stdout;
		std::string _source_dir, _compiled_module_file;
	};
}
