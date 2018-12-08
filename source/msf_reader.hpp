/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#pragma once

#include <string>
#include <vector>
#include <fstream>

namespace blink
{
	/// <summary>
	/// Class which splits a multi-stream file into its content streams.
	/// </summary>
	class msf_reader
	{
	public:
		/// <summary>
		/// Opens a multi-stream file.
		/// </summary>
		/// <param name="path">The file system path the multi-stream file is located at.</param>
		explicit msf_reader(const std::string &path);

		/// <summary>
		/// Returns whether this multi-stream file exists and is of a valid format.
		/// </summary>
		bool is_valid() const
		{
			return _is_valid;
		}

		/// <summary>
		/// Returns the number of content streams in this file.
		/// </summary>
		size_t stream_count() const
		{
			return _streams.size();
		}
		/// <summary>
		/// Gets a content stream.
		/// </summary>
		/// <param name="index">The index the stream is located at.</param>
		std::vector<char> stream(size_t index);

	private:
		struct file_header
		{
			char signature[32];
			uint32_t page_size;
			uint32_t free_page_map;
			uint32_t page_count;
			uint32_t directory_size;
			uint32_t reserved;
		};
		struct content_stream
		{
			uint32_t size;
			std::vector<uint32_t> page_indices;
		};

		std::ifstream _file_stream;
		bool _is_valid = false;
		file_header _header = {};
		std::vector<content_stream> _streams;
	};
	/// <summary>
	/// Class which provides cached reading access to the content streams of a multi-stream file.
	/// </summary>
	class msf_stream_reader
	{
	public:
		msf_stream_reader(const std::vector<char> &stream);
		msf_stream_reader(std::vector<char> &&stream);

		/// <summary>
		/// Gets the total stream size in bytes.
		/// </summary>
		size_t size() const
		{
			return _stream.size();
		}
		/// <summary>
		/// Gets the offset in bytes from stream start to the current input position.
		/// </summary>
		size_t tell() const
		{
			return _stream_offset;
		}

		/// <summary>
		/// Increases the input position without reading any data from the stream.
		/// </summary>
		/// <param name="size">An offset in bytes from the current input position to the desired input position.</param>
		void skip(size_t size)
		{
			_stream_offset += size;
		}
		/// <summary>
		/// Sets the input position.
		/// </summary>
		/// <param name="offset">An offset in bytes from stream start to the desired input position.</param>
		void seek(size_t offset)
		{
			_stream_offset = offset;
		}
		/// <summary>
		/// Aligns the current input position.
		/// </summary>
		/// <param name="align">A value to align the input position to.</param>
		void align(size_t align)
		{
			if (_stream_offset % align != 0)
			{
				skip(align - _stream_offset % align);
			}
		}

		/// <summary>
		/// Extracts data from the stream.
		/// </summary>
		/// <param name="buffer">A pointer to the byte array to store the data to.</param>
		/// <param name="size">The amount of bytes to read from the stream into the buffer.</param>
		size_t read(void *buffer, size_t size);
		/// <summary>
		/// Extracts typed data from the stream.
		/// </summary>
		template <typename T> T read()
		{
			T buffer = { };
			read(&buffer, sizeof(buffer));

			return buffer;
		}

	private:
		size_t _stream_offset = 0;
		std::vector<char> _stream;
	};

	/// <summary>
	/// Extracts a null-terminated string from the stream.
	/// </summary>
	template <> std::string msf_stream_reader::read<std::string>();
}
