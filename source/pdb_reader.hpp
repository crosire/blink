/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#pragma once

#include "msf_reader.hpp"
#include <unordered_map>
#include <filesystem>

namespace blink
{
	/// <summary>
	/// A global unique identifier (GUID).
	/// </summary>
	struct guid
	{
		uint32_t data1;
		uint32_t data2;
		uint32_t data3;
		uint32_t data4;

		bool operator==(const guid &other) { return data1 == other.data1 && data2 == other.data2 && data3 == other.data3 && data4 == other.data4; }
		bool operator!=(const guid &other) { return !operator==(other); }
	};

	/// <summary>
	/// Class which reads a program debug database.
	/// </summary>
	class pdb_reader : public msf_reader
	{
	public:
		/// <summary>
		/// Opens a program debug database file.
		/// </summary>
		/// <param name="path">The file system path the PDB file is located at.</param>
		explicit pdb_reader(const std::string &path);

		/// <summary>
		/// Returns the PDB file version.
		/// </summary>
		unsigned int version() const { return _version; }
		/// <summary>
		/// Returns the date time stamp at which the PDB file was created.
		/// </summary>
		unsigned int timestamp() const { return _timestamp; }
		/// <summary>
		/// Returns the GUID of this PDB file for matching it to its executable image file.
		/// </summary>
		guid guid() const { return _guid; }

		using msf_reader::stream;
		/// <summary>
		/// Gets a named content stream.
		/// </summary>
		/// <param name="name">The name of the stream.</param>
		std::vector<char> stream(const std::string &name)
		{
			const auto it = _named_streams.find(name);
			if (it == _named_streams.end())
				return {};
			return msf_reader::stream(it->second);
		}

		/// <summary>
		/// Walks through all symbols in this PDB file and returns them.
		/// </summary>
		void read_symbol_table(uint8_t *image_base, std::unordered_map<std::string, void *> &symbols);
		/// <summary>
		/// Returns all object file paths that were used to build the application.
		/// </summary>
		void read_object_files(std::vector<std::filesystem::path> &object_files);
		/// <summary>
		/// Returns all source code file paths that were used to build the application.
		/// </summary>
		void read_source_files(std::vector<std::vector<std::filesystem::path>> &source_files);

		/// <summary>
		/// Read linker information.
		/// </summary>
		void read_link_info(std::filesystem::path &cwd, std::string &cmd);
		/// <summary>
		/// Returns the hash table of names found in the PDB file.
		/// </summary>
		void read_name_hash_table(std::unordered_map<uint32_t, std::string> &names);

	private:
		unsigned int _version = 0, _timestamp = 0;
		struct guid _guid = {};
		std::unordered_map<std::string, unsigned int> _named_streams;
	};

	/// <summary>
	/// Class which provides cached reading access to the content streams of a multi-stream file.
	/// </summary>
	class stream_reader
	{
	public:
		stream_reader() = default;
		stream_reader(std::vector<char> &&stream) :
			_stream(std::move(stream)) {}
		stream_reader(const std::vector<char> &stream) :
			_stream(stream) {}

		/// <summary>
		/// Gets the total stream size in bytes.
		/// </summary>
		size_t size() const { return _stream.size(); }
		/// <summary>
		/// Gets the offset in bytes from stream start to the current input position.
		/// </summary>
		size_t tell() const { return _stream_offset; }

		/// <summary>
		/// Returns a pointer to the current data.
		/// </summary>
		template <typename T = char>
		T *data(size_t offset = 0) { return reinterpret_cast<T *>(_stream.data() + _stream_offset + offset); }

		/// <summary>
		/// Increases the input position without reading any data from the stream.
		/// </summary>
		/// <param name="size">An offset in bytes from the current input position to the desired input position.</param>
		void skip(size_t size) { _stream_offset += size; }
		/// <summary>
		/// Sets the input position.
		/// </summary>
		/// <param name="offset">An offset in bytes from stream start to the desired input position.</param>
		void seek(size_t offset) { _stream_offset = offset; }

		/// <summary>
		/// Aligns the current input position.
		/// </summary>
		/// <param name="align">A value to align the input position to.</param>
		void align(size_t align)
		{
			if (_stream_offset % align != 0)
				skip(align - _stream_offset % align);
		}

		/// <summary>
		/// Extracts data from the stream.
		/// </summary>
		/// <param name="buffer">A pointer to the byte array to store the data to.</param>
		/// <param name="size">The amount of bytes to read from the stream into the buffer.</param>
		size_t read(void *buffer, size_t size)
		{
			if (_stream_offset >= _stream.size())
				return 0;

			size = std::min(_stream.size() - _stream_offset, size);
			std::memcpy(buffer, _stream.data() + _stream_offset, size);
			_stream_offset += size;

			return size;
		}
		/// <summary>
		/// Extracts typed data from the stream.
		/// </summary>
		template <typename T>
		T &read()
		{
			_stream_offset += sizeof(T);
			return *reinterpret_cast<T *>(_stream.data() + _stream_offset - sizeof(T));
		}

		/// <summary>
		/// Extracts a null-terminated string from the stream.
		/// </summary>
		std::string_view read_string()
		{
			std::string_view result(_stream.data() + _stream_offset);
			_stream_offset += result.size() + 1;
			return result;
		}

	private:
		size_t _stream_offset = 0;
		std::vector<char> _stream;
	};

	/// <summary>
	/// Helper function that parses a CodeView stream and calls a callback function for every record in it
	/// </summary>
	template <typename L>
	void parse_code_view_records(stream_reader &stream, L callback, size_t alignment = 1)
	{
		// A list of records in CodeView format
		while (stream.tell() < stream.size())
		{
			// Each records starts with 2 bytes containing the size of the record after this element
			const auto size = stream.read<uint16_t>();
			// Next 2 bytes contain an enumeration depicting the type and format of the following data
			const auto code_view_tag = stream.read<uint16_t>();
			// The next record is found by adding the current record size to the position of the previous size element
			const auto next_record_offset = (stream.tell() - sizeof(size)) + size;

			callback(code_view_tag);

			stream.seek(next_record_offset);
			stream.align(alignment);
		}
	}
}
