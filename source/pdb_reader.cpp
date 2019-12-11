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
 *  - Stream 1: PDB headers and list of named streams
 *  - Stream 2: Type info (TPI stream)
 *  - Stream 3: Debug info (DBI stream)
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
struct pdb_link_info_header
{
	uint32_t cb;
	uint32_t version;
	uint32_t cwd_offset;
	uint32_t command_offset; // Example: link.exe -re -out:foo.exe
	uint32_t out_file_begin_in_command; // Example: 18 (index of 'foo.exe' in command)
	uint32_t libs_offset;
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
	uint32_t is_opened;
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
	stream_reader pdb_stream(msf_reader::stream(1));
	if (pdb_stream.size() == 0)
		return;

	const pdb_header &header = pdb_stream.read<pdb_header>();
	_version = header.version;
	_timestamp = header.time_date_stamp;
	_guid = header.guid;

	// Read stream names from string hash map
	pdb_stream.skip(header.names_map_offset);

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
		const std::string name(pdb_stream.read_string());
		pdb_stream.seek(pos); // Seek previous position in stream to read next name offset in the next iteration of this loop

		_named_streams.insert({ name, stream_index });
	}
}

void blink::pdb_reader::read_symbol_table(uint8_t *image_base, std::unordered_map<std::string, void *> &symbols)
{
	stream_reader stream(msf_reader::stream(3));

	const pdb_dbi_header &header = stream.read<pdb_dbi_header>();
	if (header.signature != 0xFFFFFFFF)
		return;

	// Find debug header stream (https://llvm.org/docs/PDB/DbiStream.html#optional-debug-header-stream)
	stream.skip(header.module_info_size + header.section_contribution_size + header.section_map_size + header.file_info_size + header.ts_map_size + header.ec_info_size);
	const pdb_dbi_debug_header &debug_header = stream.read<pdb_dbi_debug_header>();

	// Read section headers
	stream_reader section_stream(msf_reader::stream(debug_header.section_header));

	const size_t num_sections = section_stream.size() / sizeof(pdb_dbi_section_header);
	const pdb_dbi_section_header *sections = section_stream.data<pdb_dbi_section_header>();

	// Read symbol table records in CodeView format
	stream = msf_reader::stream(header.symbol_record_stream);

	parse_code_view_records(stream, stream.size(), [&](uint16_t tag) {
		if (tag != 0x110E) // S_PUB32
			return; // Skip all records that are not about public symbols

		const struct PUBSYM32 {
			uint32_t flags;
			uint32_t offset;
			uint16_t section;
			const char name[1];
		} &sym = *stream.data<const PUBSYM32>();

		if (sym.section == 0 || sym.section > num_sections)
			symbols[sym.name] = reinterpret_cast<void *>(static_cast<uintptr_t>(sym.offset)); // Relative address
		else
			symbols[sym.name] = image_base + sections[sym.section - 1].virtual_address + sym.offset; // Absolute address
	}, 4);
}

void blink::pdb_reader::read_object_files(std::vector<std::filesystem::path> &object_files)
{
	stream_reader stream(msf_reader::stream(3));

	const pdb_dbi_header &header = stream.read<pdb_dbi_header>();
	if (header.signature != 0xFFFFFFFF)
		return;

	// Read module information stream (https://llvm.org/docs/PDB/DbiStream.html#dbi-mod-info-substream)
	while (stream.tell() < sizeof(pdb_dbi_header) + header.module_info_size)
	{
		const pdb_dbi_module_info &info = stream.read<pdb_dbi_module_info>();

		const auto module_name = stream.read_string();
		const auto obj_file_name = stream.read_string(); // Contains the name of the ".lib" if this object file is part of a library

		std::filesystem::path path(module_name);

		// Find absolute path to if necessary
		if (path.is_relative())
		{
			if (info.symbol_stream != 65535 /*-1*/)
			{
				std::filesystem::path cwd;

				// Look up current working directory in symbol stream https://llvm.org/docs/PDB/ModiStream.html
				stream_reader stream(msf_reader::stream(info.symbol_stream));
				stream.skip(4); // Skip 32-bit signature (this should be CV_SIGNATURE_C13, aka 4)

				parse_code_view_records(stream, info.symbol_byte_size - 4, [&](uint16_t tag) {
					if (tag == 0x113d) // S_ENVBLOCK
					{
						stream.skip(1);
						while (stream.tell() < stream.size() && *stream.data() != '\0')
						{
							const auto key = stream.read_string();
							const std::string value(stream.read_string());

							if (key == "cwd")
							{
								cwd = value;
								return;
							}
						}
					}
				});
			
				path = cwd / path;
			}
		}

		object_files.push_back( path.string() );

		stream.align(4);
	}
}

void blink::pdb_reader::read_source_files(std::vector<std::vector<std::filesystem::path>> &source_files)
{
	stream_reader stream(msf_reader::stream(3));

	const pdb_dbi_header &header = stream.read<pdb_dbi_header>();
	if (header.signature != 0xFFFFFFFF)
		return;

	// Find file information stream (https://llvm.org/docs/PDB/DbiStream.html#file-info-substream)
	stream.skip(header.module_info_size + header.section_contribution_size + header.section_map_size);

	const uint16_t num_modules = stream.read<uint16_t>();
	stream.skip(2); // Skip old number of file names (see comment on counting the number below)

	const uint16_t *const module_file_offsets = stream.data<uint16_t>();
	const uint16_t *const module_num_source_files = stream.data<uint16_t>(num_modules * sizeof(uint16_t));
	const uint32_t *const file_name_offsets = stream.data<uint32_t>(num_modules * sizeof(uint16_t) * 2);

	// Count number of source files instead of reading the value from the header, since there may be more source files that would fit into a 16-bit value
	uint32_t num_source_files = 0;
	for (uint16_t i = 0; i < num_modules; ++i)
		num_source_files += module_num_source_files[i];

	stream.skip(num_modules * sizeof(uint16_t) * 2 + num_source_files * sizeof(uint32_t));
	const auto offset = stream.tell();

	// Append source files to array
	size_t n = source_files.size();
	source_files.resize(n + num_modules);

	for (uint32_t k = 0; k < num_modules; ++k)
	{
		uint16_t num_files = module_num_source_files[k];
		source_files[n + k].resize(num_files);

		for (uint32_t i = 0; i < num_files; ++i)
		{
			stream.seek(offset + file_name_offsets[module_file_offsets[k] + i]);
			source_files[n + k][i] = stream.read_string();
		}
	}
}

void blink::pdb_reader::read_link_info(std::filesystem::path &cwd, std::string &cmd)
{
	stream_reader stream(this->stream("/LinkInfo"));

	if (!is_valid() || stream.size() == 0)
		return;

	// See https://github.com/Microsoft/microsoft-pdb/blob/master/langapi/include/pdb.h#L500
	stream.skip(sizeof(pdb_link_info_header));

	cwd = stream.read_string();
	cmd = stream.read_string();
	// Followed by another null-terminated string with all linked libraries
}

void blink::pdb_reader::read_name_hash_table(std::unordered_map<uint32_t, std::string> &names)
{
	stream_reader stream(this->stream("/names"));

	if (!is_valid() || stream.size() == 0)
		return;

	// Read names stream
	const pdb_names_header &header = stream.read<pdb_names_header>();
	if (header.signature != 0xEFFEEFFE || header.version != 1)
		return;

	// Read the string table
	stream.skip(header.names_map_offset);

	const auto size = stream.read<uint32_t>();
	names.reserve(size);

	for (uint32_t i = 0; i < size; i++)
	{
		const auto name_offset = stream.read<uint32_t>();

		// Skip empty entries
		if (name_offset == 0)
			continue;

		const auto pos = stream.tell();
		stream.seek(sizeof(header) + name_offset);
		const std::string name(stream.read_string());
		stream.seek(pos); // Seek previous position in stream to read next name offset in the next iteration of this loop

		names.insert({ i, name });
	}
}
