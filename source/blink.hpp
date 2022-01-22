/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#pragma once

#include "pdb_reader.hpp"
#include "scoped_handle.hpp"
#include <vector>
#include <string>
#include <filesystem>
#include <unordered_set>
#include <unordered_map>
#include <Windows.h>

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
		class notification_info
		{
			public:
				notification_info() : p_info(buffer_size), overlapped({ 0 }) {}

			const size_t buffer_size = 4096;
			std::vector<BYTE> p_info;
			OVERLAPPED overlapped;
		};

		template <typename SYMBOL_TYPE, typename HEADER_TYPE>
		bool link(void *const object_file, const HEADER_TYPE &header);

		bool read_debug_info(const uint8_t *image_base);
		void read_import_address_table(const uint8_t *image_base);

		bool set_watch(
			const size_t dir_index,
			std::vector<scoped_handle> &dir_handles,
			std::vector<scoped_handle> &event_handles,
			std::vector<notification_info> &notification_infos);
		std::string build_compile_command_line(const std::filesystem::path &source_file, std::filesystem::path &object_file) const;

		uint8_t *_image_base = nullptr;
		std::vector<std::filesystem::path> _source_dirs;
		std::vector<std::filesystem::path> _object_files;
		std::vector<std::vector<std::filesystem::path>> _source_files;
		source_file_map _source_file_map;
		std::unordered_map<std::string, void *> _symbols;
		std::unordered_map<std::string, uint32_t> _last_modifications;
	};
}
