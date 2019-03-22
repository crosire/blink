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
		template <typename SYMBOL_TYPE, typename HEADER_TYPE>
		bool link(void *const object_file, const HEADER_TYPE &header);

		std::string build_compile_command_line(const std::filesystem::path &source_file, std::filesystem::path &object_file) const;

		template <typename T>
		T read_symbol(const std::string &name) const
		{
			if (const auto it = _symbols.find(name); it != _symbols.end())
				return *reinterpret_cast<T *>(it->second);
			return T();
		}
		template <typename T = void, typename... Args>
		T call_symbol(const std::string &name, Args... args) const
		{
			if (const auto it = _symbols.find(name); it != _symbols.end())
				return reinterpret_cast<T(*)(Args...)>(it->second)(std::forward<Args>(args)...);
			return T();
		}

	private:
		uint8_t *_image_base = nullptr;
		std::filesystem::path _source_dir;
		std::vector<std::filesystem::path> _object_files;
		std::vector<std::vector<std::filesystem::path>> _source_files;
		std::unordered_map<std::string, void *> _symbols;
		std::unordered_map<std::string, uint32_t> _last_modifications;
	};
}
