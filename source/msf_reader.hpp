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
		bool is_valid() const { return _is_valid; }

		/// <summary>
		/// Returns the number of content streams in this file.
		/// </summary>
		size_t stream_count() const { return _streams.size(); }
		/// <summary>
		/// Gets a content stream.
		/// </summary>
		/// <param name="index">The index the stream is located at.</param>
		std::vector<char> stream(size_t index);

	protected:
		struct content_stream
		{
			uint32_t size;
			std::vector<uint32_t> page_indices;
		};

		bool _is_valid = false;
		std::vector<content_stream> _streams;

	private:
		uint32_t _page_size;
		std::ifstream _file_stream;
	};
}
