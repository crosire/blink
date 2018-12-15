/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "msf_reader.hpp"
#include <algorithm>

/**
 * Microsoft C/C++ MSF 7.00 (MSF = multi-stream file / compound file)
 *
 * Raw file is subdivided into pages of fixed size.
 * Those pages are grouped into content streams of variable size.
 * The stream assignments to corresponding pages are defined in the root directory (and stream zero).
 */

struct msf_file_header
{
	char signature[32];
	uint32_t page_size;
	uint32_t free_page_map;
	uint32_t page_count;
	uint32_t directory_size;
	uint32_t reserved;
};

static inline uint32_t calc_page_count(uint32_t size, uint32_t page_size)
{
	return (size + page_size - 1u) / page_size;
}

blink::msf_reader::msf_reader(const std::string &path) :
	_file_stream(path, std::ios::in | std::ios::binary)
{
	if (!_file_stream.is_open())
		return;

	// Read and verify MSF header from file
	msf_file_header header;
	_file_stream.read(reinterpret_cast<char *>(&header), sizeof(header));

	static constexpr char signature[] = "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0";

	if (_file_stream.bad() || std::memcmp(header.signature, signature, sizeof(signature)) != 0)
		return;

	// Read root directory
	const auto num_root_pages = calc_page_count(header.directory_size, header.page_size);
	const auto num_root_index_pages = calc_page_count(num_root_pages * 4, header.page_size);
	std::vector<uint32_t> root_pages(num_root_pages);
	std::vector<uint32_t> root_index_pages(num_root_index_pages);

	if (num_root_index_pages == 0)
		return;

	_page_size = header.page_size;

	_file_stream.read(reinterpret_cast<char *>(root_index_pages.data()), num_root_index_pages * 4);

	for (uint32_t i = 0, k = 0, len; i < num_root_index_pages; i++, k += len)
	{
		len = std::min(_page_size / 4, num_root_pages - k);

		_file_stream.seekg(root_index_pages[i] * _page_size);
		_file_stream.read(reinterpret_cast<char *>(&root_pages[k]), len * 4);
	}

	// Read content stream sizes
	uint32_t current_root_page = 0;

	for (uint32_t i = 0, j = 0; i < num_root_pages; i++)
	{
		_file_stream.seekg(root_pages[i] * _page_size);

		if (i == 0)
		{
			_file_stream.read(reinterpret_cast<char *>(&j), sizeof(j));
			_streams.reserve(j);
		}

		for (uint32_t k = i == 0, size; j > 0 && k < _page_size / 4; k++, j--)
		{
			_file_stream.read(reinterpret_cast<char *>(&size), sizeof(size));
			if (0xFFFFFFFF == size)
				size = 0;
			_streams.push_back({ size });
		}

		if (j == 0)
		{
			current_root_page = i;
			break;
		}
	}

	// Read content stream page indices (located directly after stream sizes)
	for (content_stream &stream : _streams)
	{
		uint32_t num_pages = calc_page_count(stream.size, _page_size);
		if (num_pages == 0)
			continue;

		stream.page_indices.resize(num_pages);

		for (uint32_t num_pages_remaining = num_pages; num_pages_remaining > 0;)
		{
			const auto page_off = static_cast<uint32_t>(_file_stream.tellg()) % _page_size;
			const auto page_size = std::min(num_pages_remaining * 4, _page_size - page_off);

			_file_stream.read(reinterpret_cast<char *>(stream.page_indices.data() + num_pages - num_pages_remaining), page_size);

			num_pages_remaining -= page_size / 4;

			// Advance to next root page
			if (page_off + page_size == _page_size)
				_file_stream.seekg(root_pages[++current_root_page] * _page_size);
		}
	}

	_is_valid = _file_stream.good();
}

std::vector<char> blink::msf_reader::stream(size_t index)
{
	const content_stream &stream = _streams[index];

	size_t offset = 0;
	std::vector<char> stream_data( // Allocate enough memory to hold all associated pages
		stream.page_indices.size() * _page_size);

	// Iterate through all pages associated with this stream and read their data
	for (uint32_t page_index : stream.page_indices)
	{
		_file_stream.seekg(page_index * _page_size);
		_file_stream.read(stream_data.data() + offset, _page_size);

		offset += _page_size;
	}

	// Shrink result to the actual stream size
	stream_data.resize(stream.size);

	return stream_data;
}
