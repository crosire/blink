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

	msf_reader::msf_reader(const std::string &path) : _file(path, std::ios::in | std::ios::binary)
	{
		if (!_file.is_open())
		{
			return;
		}

		// Read file header
		_file.read(reinterpret_cast<char *>(&_header), sizeof(_header));

		const char signature[] = "Microsoft C/C++ MSF 7.00\r\n\032DS\0\0";

		if (_file.bad() || memcmp(_header.signature, signature, sizeof(signature)) != 0)
		{
			return;
		}

		// Read root directory
		const uint32_t num_root_pages = calc_page_count(_header.directory_size, _header.page_size);
		const uint32_t num_root_index_pages = calc_page_count(num_root_pages * 4, _header.page_size);
		std::vector<uint32_t> root_pages(num_root_pages);
		std::vector<uint32_t> root_index_pages(num_root_index_pages);

		if (num_root_index_pages == 0)
		{
			return;
		}

		_file.read(reinterpret_cast<char *>(root_index_pages.data()), num_root_index_pages * 4);

		for (unsigned int i = 0, k = 0, len; i < num_root_index_pages; i++, k += len)
		{
			len = std::min(_header.page_size / 4, num_root_pages - k);

			_file.seekg(root_index_pages[i] * _header.page_size);
			_file.read(reinterpret_cast<char *>(&root_pages[k]), len * 4);
		}

		// Read content stream sizes
		unsigned int current_root_page = 0;

		for (unsigned int i = 0, j = 0; i < num_root_pages; i++)
		{
			_file.seekg(root_pages[i] * _header.page_size);

			if (i == 0)
			{
				_file.read(reinterpret_cast<char *>(&j), 4);

				_streams.reserve(j);
			}

			for (unsigned int k = i == 0; j > 0 && k < _header.page_size / 4; k++, j--)
			{
				uint32_t size = 0;
				_file.read(reinterpret_cast<char *>(&size), 4);

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
				const unsigned int page_offset = static_cast<unsigned int>(_file.tellg()) % _header.page_size;
				const unsigned int size = std::min(num_pages_remaining * 4, _header.page_size - page_offset);

				_file.read(reinterpret_cast<char *>(stream.page_indices.data() + num_pages - num_pages_remaining), size);

				num_pages_remaining -= size / 4;

				if (page_offset + size == _header.page_size)
				{
					// Advance to next root page
					_file.seekg(root_pages[++current_root_page] * _header.page_size);
				}
			}
		}

		// Verify file
		_is_valid = _file.good();
	}

	std::unique_ptr<msf_stream_reader> msf_reader::stream(unsigned int index)
	{
		if (index >= stream_count())
		{
			return nullptr;
		}

		return std::unique_ptr<msf_stream_reader>(new msf_stream_reader(this, index));
	}

	msf_stream_reader::msf_stream_reader(msf_reader *reader, unsigned int stream_index) : _reader(reader), _stream_index(stream_index)
	{
	}

	bool msf_stream_reader::read(void *buffer, size_t size)
	{
	continue_reading:
		const auto page_index = (_stream_offset) / _reader->_header.page_size;
		const auto page_index_last = (_stream_offset + size) / _reader->_header.page_size;

		_reader->_file.seekg(_reader->_streams[_stream_index].page_indices[page_index] * _reader->_header.page_size + _stream_offset % _reader->_header.page_size);

		if (page_index != page_index_last)
		{
			const auto offset = _reader->_header.page_size - _stream_offset % _reader->_header.page_size;

			_reader->_file.read(static_cast<char *>(buffer), offset);

			size -= offset;
			buffer = static_cast<unsigned char *>(buffer) + offset;
			_stream_offset += offset;

			if (size != 0)
			{
				goto continue_reading;
			}
		}
		else
		{
			_reader->_file.read(static_cast<char *>(buffer), size);
			_stream_offset += size;
		}

		return _reader->_file.good();
	}
	template <> std::string msf_stream_reader::read<std::string>()
	{
		char buffer[128];
		std::string result;

		while (read(buffer, sizeof(buffer)))
		{
			const auto end_pos = buffer + 128;
			const auto null_pos = std::find(buffer, end_pos, '\0');

			if (null_pos != end_pos)
			{
				_stream_offset -= end_pos - null_pos - 1u;

				result += buffer;
				break;
			}
			else
			{
				result += std::string(buffer, end_pos);
			}
		}

		return result;
	}
}
