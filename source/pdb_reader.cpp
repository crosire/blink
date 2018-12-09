/**
 * Copyright (C) 2016 Patrick Mours. All rights reserved.
 * License: https://github.com/crosire/blink#license
 */

#include "pdb_reader.hpp"
#include <unordered_set>

/**
 * Microsoft program debug database file
 *
 * File is a multi-stream file with various different data streams. Some streams are located at a fixed index:
 *  - Stream 0: MSF root directory copy
 *  - Stream 1: PDB headers and list of named streams
 *  - Stream 2: Type info (TPI stream)
 *  - Stream 3: Debug info (DBI stream)
 *  - Stream 4: Build info, UDT source file + line info and some function identifiers (TPI header followed by CodeView records)
 */

#pragma region PDB Headers
#pragma pack(1)

struct pdb_header
{
	uint32_t version;
	uint32_t time_date_stamp;
	uint32_t age;
	blink::guid guid;
	uint32_t names_map_offset;
};
struct pdb_names_header
{
	uint32_t signature;
	uint32_t version;
	uint32_t names_map_offset;
};

struct pdb_dbi_header
{
	uint32_t signature;
	uint32_t version;
	uint32_t age;
	uint16_t global_symbol_info_stream;
	uint16_t pdb_dll_version;
	uint16_t public_symbol_info_stream;
	uint16_t pdb_dll_build_major;
	uint16_t symbol_record_stream;
	uint16_t pdb_dll_build_minor;
	uint32_t module_info_size;
	uint32_t section_contribution_size;
	uint32_t section_map_size;
	uint32_t file_info_size;
	uint32_t ts_map_size;
	uint32_t mfc_index;
	uint32_t debug_header_size;
	uint32_t ec_info_size;
	uint16_t flags;
	uint16_t machine;
	uint32_t reserved;
};
struct pdb_dbi_debug_header
{
	uint16_t fpo;
	uint16_t exception;
	uint16_t fixup;
	uint16_t omap_to_src;
	uint16_t omap_from_src;
	uint16_t section_header;
	uint16_t token_rid_map;
	uint16_t xdata;
	uint16_t pdata;
	uint16_t new_fpo;
	uint16_t section_header_orig;
};
struct pdb_dbi_section_header
{
	char name[8];
	uint32_t size;
	uint32_t virtual_address;
	uint32_t data_size;
	uint32_t raw_data_rva;
	uint32_t relocation_table_rva;
	uint32_t line_numbers_rva;
	uint16_t num_relocations;
	uint16_t num_line_numbers;
	uint32_t flags;
};
#pragma endregion

blink::pdb_reader::pdb_reader(const std::string &path) : msf_reader(path)
{
	if (!msf_reader::is_valid() || msf_reader::stream_count() <= 4)
		return;

	// Read PDB info stream
	msf_stream_reader pdbstream(msf_reader::stream(1));

	if (pdbstream.size() == 0)
		return;

	const auto pdbheader = pdbstream.read<pdb_header>();

	_version = pdbheader.version;
	_timestamp = pdbheader.time_date_stamp;
	_guid = pdbheader.guid;

	// Read stream names from string hash map
	pdbstream.seek(sizeof(pdb_header) + pdbheader.names_map_offset);
	const auto count = pdbstream.read<uint32_t>();
	const auto hash_table_size = pdbstream.read<uint32_t>();

	_named_streams.reserve(count);

	const auto num_bitset_present = pdbstream.read<uint32_t>();
	std::vector<uint32_t> bitset_present(num_bitset_present);
	pdbstream.read(bitset_present.data(), num_bitset_present * sizeof(uint32_t));
	const auto num_bitset_deleted = pdbstream.read<uint32_t>();
	pdbstream.skip(num_bitset_deleted * sizeof(uint32_t));

	for (unsigned int i = 0; i < hash_table_size; i++)
	{
		if ((bitset_present[i / 32] & (1 << (i % 32))) == 0)
			continue;

		const auto name_offset = pdbstream.read<uint32_t>();
		const auto stream_index = pdbstream.read<uint32_t>();

		const auto oldpos = pdbstream.tell();
		pdbstream.seek(sizeof(pdb_header) + name_offset);
		const auto name = pdbstream.read<std::string>();
		pdbstream.seek(oldpos);

		_named_streams.insert({ name, stream_index });
	}

	_is_valid = stream_count() > 4;
}

std::unordered_map<std::string, uintptr_t> blink::pdb_reader::symbols(uintptr_t image_base)
{
	// Read debug info (DBI stream)
	msf_stream_reader stream(msf_reader::stream(3));
	const auto dbiheader = stream.read<pdb_dbi_header>();

	if (dbiheader.signature != 0xFFFFFFFF)
		return {};

	// Read section headers
	stream.seek(sizeof(pdb_dbi_header) + dbiheader.module_info_size + dbiheader.section_contribution_size + dbiheader.section_map_size + dbiheader.file_info_size + dbiheader.ts_map_size + dbiheader.ec_info_size);
	const auto dbgheader = stream.read<pdb_dbi_debug_header>();
	msf_stream_reader sectionstream(msf_reader::stream(dbgheader.section_header));

	std::vector<pdb_dbi_section_header> sections;
	sections.reserve(sectionstream.size() / sizeof(pdb_dbi_section_header));

	while (sectionstream.tell() < sectionstream.size())
	{
		// The section header stream is a tightly packed list of section header structures
		sections.push_back(std::move(sectionstream.read<pdb_dbi_section_header>()));
	}

	// Read symbol table
	stream = msf_reader::stream(dbiheader.symbol_record_stream);
	std::unordered_map<std::string, uintptr_t> symbols;

	// A list of records in CodeView format
	while (stream.tell() < stream.size())
	{
		// Each records starts with 2 bytes containing the size of the record after this element
		const auto size = stream.read<uint16_t>();
		// Next 2 bytes contain an enumeration depicting the type and format of the following data
		const auto tag = stream.read<uint16_t>();
		// The next record is found by adding the current record size to the position of the previous size element
		const auto next_record_offset = (stream.tell() - sizeof(uint16_t)) + size;

		if (tag == 0x110E) // S_PUB32
		{
			struct leaf_data
			{
				uint32_t is_code : 1;
				uint32_t is_function : 1;
				uint32_t is_managed : 1;
				uint32_t is_managed_il : 1;
				uint32_t padding : 28;
				uint32_t offset;
				uint16_t segment;
			};

			const auto info = stream.read<leaf_data>();
			const auto mangled_name = stream.read<std::string>();

			if (info.segment == 0 || info.segment > sections.size())
				symbols[mangled_name] = info.offset; // Relative address
			else
				symbols[mangled_name] = image_base + info.offset + sections[info.segment - 1].virtual_address; // Absolute address
		}

		stream.seek(next_record_offset);

		// Each element is aligned to 4-byte boundary
		stream.align(4);
	}

	return symbols;
}

std::vector<std::string> blink::pdb_reader::sourcefiles()
{
	// Read debug info (DBI stream)
	msf_stream_reader stream(msf_reader::stream(3));
	const auto dbiheader = stream.read<pdb_dbi_header>();

	if (dbiheader.signature != 0xFFFFFFFF)
		return {};

	// https://llvm.org/docs/PDB/DbiStream.html#file-info-substream
	stream.seek(sizeof(pdb_dbi_header) + dbiheader.module_info_size + dbiheader.section_contribution_size + dbiheader.section_map_size);
	const uint16_t num_modules = stream.read<uint16_t>();
	stream.skip(2 + num_modules * 2);

	uint32_t num_source_files = 0;
	for (uint16_t i = 0; i < num_modules; ++i)
		num_source_files += stream.read<uint16_t>();

	std::vector<uint32_t> file_name_offsets;
	file_name_offsets.reserve(num_source_files);
	for (uint32_t i = 0; i < num_source_files; ++i)
		file_name_offsets.push_back(stream.read<uint32_t>());

	auto offset = stream.tell();

	std::vector<std::string> source_files;
	source_files.reserve(num_source_files);
	for (uint32_t i = 0; i < num_source_files; ++i)
	{
		stream.seek(offset + file_name_offsets[i]);

		const std::string source_file = stream.read<std::string>();
		source_files.push_back(source_file);
	}

	return source_files;
}

std::unordered_map<unsigned int, std::string> blink::pdb_reader::names()
{
	msf_stream_reader stream(this->stream("/names"));

	if (!is_valid() || stream.size() == 0)
		return {};

	// Read names stream
	const auto header = stream.read<pdb_names_header>();

	if (header.signature != 0xEFFEEFFE || header.version != 1)
		return {};

	// Read string hash table
	stream.seek(sizeof(pdb_names_header) + header.names_map_offset);
	const auto size = stream.read<uint32_t>();

	std::unordered_map<unsigned int, std::string> names;
	names.reserve(size);

	for (unsigned int i = 0; i < size; i++)
	{
		const auto name_offset = stream.read<uint32_t>();

		if (name_offset == 0)
			continue;

		const auto oldpos = stream.tell();
		stream.seek(sizeof(pdb_names_header) + name_offset);
		const auto name = stream.read<std::string>();
		stream.seek(oldpos);

		names.insert({ i, name });
	}

	return names;
}
