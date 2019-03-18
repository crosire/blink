/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#pragma once

#include <vector>
#include <string>
#include <filesystem>
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

		void run();
		bool link(const std::filesystem::path &object_file);

		bool build_compile_command_lines(const std::filesystem::path &source_file, bool is_header_file, std::vector<std::pair<std::string, std::filesystem::path>> &cmd_lines) const;

	private:
		uint8_t *_image_base = nullptr;
		std::filesystem::path _source_dir;
		std::vector<std::filesystem::path> _object_files;
		std::vector<std::vector<std::filesystem::path>> _source_files;
		std::unordered_map<std::string, void *> _symbols;
		std::unordered_map<std::string, uint32_t> _last_modifications;
	};
}
