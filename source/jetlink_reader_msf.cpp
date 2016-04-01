#include "jetlink_reader_msf.hpp"
#include <algorithm>

/**
 * Microsoft C/C++ MSF 7.00 (MSF = multi-stream file / compound file)
 *
 * Raw file is subdivided into pages of fixed size.
 * Those pages are grouped into content streams of variable size.
 * The stream assignments to corresponding pages are defined in the root directory (and stream zero).
 */

namespace jetlink
{
	namespace
	{
		uint32_t calc_page_count(uint32_t size, uint32_t page_size)
		{
			return (size + page_size - 1u) / page_size;
		}
	}

	msf_reader::msf_reader(const std::string &path) : _file_stream(path, std::ios::in | std::ios::binary)
	{
		if (!_file_stream.is_open())
		{
			return;
		}

		// Read file header
		_file_stream.read(reinterpret_cast<char *>(&_header), sizeof(_header));

		const char signature[] = "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0";

		if (_file_stream.bad() || std::memcmp(_header.signature, signature, sizeof(signature)) != 0)
		{
			return;
		}

		// Read root directory
		const auto num_root_pages = calc_page_count(_header.directory_size, _header.page_size);
		const auto num_root_index_pages = calc_page_count(num_root_pages * 4, _header.page_size);
		std::vector<uint32_t> root_pages(num_root_pages);
		std::vector<uint32_t> root_index_pages(num_root_index_pages);

		if (num_root_index_pages == 0)
		{
			return;
		}

		_file_stream.read(reinterpret_cast<char *>(root_index_pages.data()), num_root_index_pages * 4);

		for (uint32_t i = 0, k = 0, len; i < num_root_index_pages; i++, k += len)
		{
			len = std::min(_header.page_size / 4, num_root_pages - k);

			_file_stream.seekg(root_index_pages[i] * _header.page_size);
			_file_stream.read(reinterpret_cast<char *>(&root_pages[k]), len * 4);
		}

		// Read content stream sizes
		uint32_t current_root_page = 0;

		for (uint32_t i = 0, j = 0; i < num_root_pages; i++)
		{
			_file_stream.seekg(root_pages[i] * _header.page_size);

			if (i == 0)
			{
				_file_stream.read(reinterpret_cast<char *>(&j), 4);

				_streams.reserve(j);
			}

			for (unsigned int k = i == 0; j > 0 && k < _header.page_size / 4; k++, j--)
			{
				uint32_t size = 0;
				_file_stream.read(reinterpret_cast<char *>(&size), 4);

				if (size == 0xFFFFFFFF)
				{
					size = 0;
				}

				_streams.push_back({ size });
			}

			if (j == 0)
			{
				current_root_page = i;
				break;
			}
		}

		// Read content stream page indices (located directly after stream sizes)
		for (auto &stream : _streams)
		{
			const uint32_t num_pages = calc_page_count(stream.size, _header.page_size);

			if (num_pages == 0)
			{
				continue;
			}

			stream.page_indices.resize(num_pages);

			for (unsigned int num_pages_remaining = num_pages; num_pages_remaining > 0;)
			{
				const auto page_offset = static_cast<uint32_t>(_file_stream.tellg()) % _header.page_size;
				const auto size = std::min(num_pages_remaining * 4, _header.page_size - page_offset);

				_file_stream.read(reinterpret_cast<char *>(stream.page_indices.data() + num_pages - num_pages_remaining), size);

				num_pages_remaining -= size / 4;

				if (page_offset + size == _header.page_size)
				{
					// Advance to next root page
					_file_stream.seekg(root_pages[++current_root_page] * _header.page_size);
				}
			}
		}

		// Verify file
		_is_valid = _file_stream.good();
	}

	std::unique_ptr<msf_stream_reader> msf_reader::stream(size_t index)
	{
		if (index >= stream_count())
		{
			return nullptr;
		}

		const auto &stream = _streams[index];
		std::vector<char> stream_data(stream.page_indices.size() * _header.page_size);
		size_t offset = 0;

		for (auto page_index : stream.page_indices)
		{
			_file_stream.seekg(page_index * _header.page_size);
			_file_stream.read(stream_data.data() + offset, _header.page_size);

			offset += _header.page_size;
		}

		stream_data.resize(stream.size);

		return std::make_unique<msf_stream_reader>(std::move(stream_data));
	}

	msf_stream_reader::msf_stream_reader(std::vector<char> &&stream) : _stream(std::move(stream))
	{
	}

	size_t msf_stream_reader::read(void *buffer, size_t size)
	{
		if (_stream_offset >= _stream.size())
		{
			return 0;
		}

		size = std::min(_stream.size() - _stream_offset, size);
		std::memcpy(buffer, _stream.data() + _stream_offset, size);
		_stream_offset += size;

		return size;
	}
	template <>
	std::string msf_stream_reader::read<std::string>()
	{
		std::string result;

		while (_stream_offset < _stream.size())
		{
			const auto c = _stream[_stream_offset++];

			if (c == '\0')
			{
				break;
			}

			result += c;
		}

		return result;
	}
}
