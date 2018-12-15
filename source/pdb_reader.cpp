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
 *  - Stream 0: Previous MSF root directory
 *  - Stream 1: PDB headers and list of named streams
 *  - Stream 2: Type info (TPI stream)
 *  - Stream 3: Debug info (DBI stream)
 *  - Stream 4: CodeView records (IPI stream)
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
	uint16_t toolchain_major : 8;
	uint16_t toolchain_minor : 7;
	uint16_t new_version_format : 1;
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
	uint16_t incrementally_linked : 1;
	uint16_t private_symbols_stripped : 1;
	uint16_t has_conflicting_types : 1;
	uint16_t padding1 : 13;
	uint16_t machine;
	uint32_t padding2;
};
struct pdb_dbi_module_info
{
	uint32_t opened;
	struct {
		uint16_t index;
		uint16_t padding1;
		uint32_t offset;
		uint32_t size;
		uint32_t characteristics;
		uint16_t module_index;
		uint16_t padding2;
		uint32_t data_crc;
		uint32_t relocation_crc;
	} section;
	uint16_t is_dirty : 1;
	uint16_t has_ec_info : 1;
	uint16_t padding1 : 6;
	uint16_t type_server_index : 8;
	uint16_t symbol_stream;
	uint32_t symbol_byte_size;
	uint32_t old_lines_byte_size;
	uint32_t lines_byte_size;
	uint16_t num_source_files;
	uint16_t padding2;
	uint32_t offsets;
	uint32_t source_file_name_index;
	uint32_t pdb_file_name_index;
};
struct pdb_dbi_debug_header
{
	uint16_t fpo; // IMAGE_DEBUG_TYPE_FPO
	uint16_t exception; // IMAGE_DEBUG_TYPE_EXCEPTION
	uint16_t fixup; // IMAGE_DEBUG_TYPE_FIXUP
	uint16_t omap_to_src; // IMAGE_DEBUG_TYPE_OMAP_TO_SRC
	uint16_t omap_from_src; // IMAGE_DEBUG_TYPE_OMAP_FROM_SRC
	uint16_t section_header; // A dump of all section headers from the executable
	uint16_t token_rid_map;
	uint16_t xdata; // A dump of the .xdata section from the executable
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
	// PDB files should have 4 streams at the beginning that are always at the same index
	_is_valid &= stream_count() > 4;

	if (!is_valid())
		return;

	// Read PDB info stream
	msf_stream_reader pdb_stream = msf_reader::stream(1);

	if (pdb_stream.size() == 0)
		return;

	const pdb_header header = pdb_stream.read<pdb_header>();
	_version = header.version;
	_timestamp = header.time_date_stamp;
	_guid = header.guid;

	// Read stream names from string hash map
	pdb_stream.seek(sizeof(header) + header.names_map_offset);

	const auto count = pdb_stream.read<uint32_t>();
	const auto hash_table_size = pdb_stream.read<uint32_t>();
	_named_streams.reserve(count);

	const auto num_bitset_present = pdb_stream.read<uint32_t>();
	std::vector<uint32_t> bitset_present(num_bitset_present);
	pdb_stream.read(bitset_present.data(), num_bitset_present * sizeof(uint32_t));

	const auto num_bitset_deleted = pdb_stream.read<uint32_t>();
	pdb_stream.skip(num_bitset_deleted * sizeof(uint32_t));

	for (uint32_t i = 0; i < hash_table_size; i++)
	{
		if ((bitset_present[i / 32] & (1 << (i % 32))) == 0)
			continue;

		const auto name_offset = pdb_stream.read<uint32_t>();
		const auto stream_index = pdb_stream.read<uint32_t>();

		const auto pos = pdb_stream.tell();
		pdb_stream.seek(sizeof(header) + name_offset); // Seek into the string table that stores the name
		const auto name = pdb_stream.read<std::string>();
		pdb_stream.seek(pos); // Seek previous position in stream to read next name offset in the next iteration of this loop

		_named_streams.insert({ name, stream_index });
	}
}

void blink::pdb_reader::read_symbol_table(uint8_t *image_base, std::unordered_map<std::string, void *> &symbols)
{
	msf_stream_reader stream(msf_reader::stream(3));

	const pdb_dbi_header header = stream.read<pdb_dbi_header>();
	if (header.signature != 0xFFFFFFFF)
		return;

	// Find debug header stream (https://llvm.org/docs/PDB/DbiStream.html#optional-debug-header-stream)
	stream.seek(sizeof(pdb_dbi_header) + header.module_info_size + header.section_contribution_size + header.section_map_size + header.file_info_size + header.ts_map_size + header.ec_info_size);
	const pdb_dbi_debug_header debug_header = stream.read<pdb_dbi_debug_header>();

	// Read section headers
	msf_stream_reader section_stream(msf_reader::stream(debug_header.section_header));
	std::vector<pdb_dbi_section_header> sections;
	sections.reserve(section_stream.size() / sizeof(pdb_dbi_section_header));
	// The section header stream is a tightly packed list of section header structures
	while (section_stream.tell() < section_stream.size())
		sections.push_back(std::move(section_stream.read<pdb_dbi_section_header>()));

	// Read symbol table
	stream = msf_reader::stream(header.symbol_record_stream);

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
				symbols[mangled_name] = reinterpret_cast<void *>(static_cast<uintptr_t>(info.offset)); // Relative address
			else
				symbols[mangled_name] = image_base + info.offset + sections[info.segment - 1].virtual_address; // Absolute address
		}

		stream.seek(next_record_offset);

		// Each element is aligned to 4-byte boundary
		stream.align(4);
	}
}

void blink::pdb_reader::read_object_files(std::vector<std::filesystem::path> &object_files)
{
	msf_stream_reader stream(msf_reader::stream(3));

	const pdb_dbi_header header = stream.read<pdb_dbi_header>();
	if (header.signature != 0xFFFFFFFF)
		return;

	// Read module information stream (https://llvm.org/docs/PDB/DbiStream.html#dbi-mod-info-substream)
	while (stream.tell() < sizeof(pdb_dbi_header) + header.module_info_size)
	{
		const auto info = stream.read<pdb_dbi_module_info>();
		const auto module_name = stream.read<std::string>();
		const auto obj_file_name = stream.read<std::string>(); // Contains the name of the ".lib" if this object file is part of a library

		object_files.push_back(module_name);

		stream.align(4);
	}
}

void blink::pdb_reader::read_source_files(std::vector<std::filesystem::path> &source_files)
{
	msf_stream_reader stream(msf_reader::stream(3));

	const pdb_dbi_header header = stream.read<pdb_dbi_header>();
	if (header.signature != 0xFFFFFFFF)
		return;

	// Find file information stream (https://llvm.org/docs/PDB/DbiStream.html#file-info-substream)
	stream.seek(sizeof(pdb_dbi_header) + header.module_info_size + header.section_contribution_size + header.section_map_size);

	const uint16_t num_modules = stream.read<uint16_t>();
	stream.skip(2 + num_modules * 2); // Skip module indices

	// Sum number of source files instead of reading the value from the header, since there may be more source files that would fit into a 16-bit value
	uint32_t num_source_files = 0;
	for (uint16_t i = 0; i < num_modules; ++i)
		num_source_files += stream.read<uint16_t>();

	std::vector<uint32_t> file_name_offsets;
	file_name_offsets.reserve(num_source_files);
	for (uint32_t i = 0; i < num_source_files; ++i)
		file_name_offsets.push_back(stream.read<uint32_t>());

	auto offset = stream.tell();

	source_files.reserve(num_source_files);
	for (uint32_t i = 0; i < num_source_files; ++i)
	{
		stream.seek(offset + file_name_offsets[i]);

		const std::string source_file = stream.read<std::string>();
		source_files.push_back(source_file);
	}
}

void blink::pdb_reader::read_name_hash_table(std::unordered_map<uint32_t, std::string> &names)
{
	msf_stream_reader stream(this->stream("/names"));

	if (!is_valid() || stream.size() == 0)
		return;

	// Read names stream
	const auto header = stream.read<pdb_names_header>();
	if (header.signature != 0xEFFEEFFE || header.version != 1)
		return;

	// Read string table
	stream.seek(sizeof(pdb_names_header) + header.names_map_offset);

	const auto size = stream.read<uint32_t>();
	names.reserve(size);

	for (uint32_t i = 0; i < size; i++)
	{
		const auto name_offset = stream.read<uint32_t>();

		// Skip empty entries
		if (name_offset == 0)
			continue;

		const auto pos = stream.tell();
		stream.seek(sizeof(pdb_names_header) + name_offset);
		const auto name = stream.read<std::string>();
		stream.seek(pos); // Seek previous position in stream to read next name offset in the next iteration of this loop

		names.insert({ i, name });
	}
}
