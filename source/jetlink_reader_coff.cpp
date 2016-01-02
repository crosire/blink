#include "jetlink_reader_coff.hpp"
#include <algorithm>

/**
 * Common Object File Format (COFF) file
 *
 * File is subdivided into different section blocks.
 * Object files with debugging information contain some predefined sections:
 *  - debug$F: Contains frame pointer omission information (list of FPO_DATA records)
 *  - debug$S: Contains symbol information (list of CodeView symbol records)
 *  - debug$T: Contains type information (list of CodeView type records)
 */

#pragma pack(1)

namespace jetlink
{
	namespace
	{
		struct coff_section_header
		{
			char name[8];
			uint32_t zero;
			uint32_t virtual_address;
			uint32_t data_size;
			uint32_t raw_data_rva;
			uint32_t relocation_table_rva;
			uint32_t line_numbers_rva;
			uint16_t num_relocations;
			uint16_t num_line_numbers;
			uint32_t flags;
		};
		struct coff_symbol
		{
			union {
				char name[8];
				struct {
					uint32_t name_zeroes;
					uint32_t name_offset;
				};
			};
			uint32_t value;
			uint16_t section;
			uint16_t type;
			uint8_t storage_class;
			uint8_t num_aux_symbols;
		};
		struct coff_relocation
		{
			uint32_t address;
			uint32_t symbol_table_index;
			uint16_t type;
		};

		class file_stream_reader
		{
		public:
			file_stream_reader(std::fstream &stream) : _stream(&stream)
			{
			}

			std::streamsize size() const
			{
				const auto oldpos = _stream->tellg();
				_stream->seekg(0, std::ios::end);
				const auto size = _stream->tellg();
				_stream->seekg(oldpos);
				return size;
			}
			std::streampos tell() const
			{
				return _stream->tellg();
			}

			void skip(std::streamsize size)
			{
				_stream->ignore(size);
			}
			void seek(std::streampos offset)
			{
				_stream->clear();
				_stream->seekg(offset);
			}

			bool read(void *buffer, size_t size)
			{
				_stream->read(static_cast<char *>(buffer), size);
				return _stream->good();
			}
			template <typename T> T read()
			{
				T buffer = {};
				read(&buffer, sizeof(T));

				return buffer;
			}
			template <> std::string read<std::string>()
			{
				char buffer[128];
				const auto buffer_beg = buffer;
				const auto buffer_end = buffer + 128;

				std::string result;

				while (read(buffer, sizeof(buffer)))
				{
					const auto null_pos = std::find(buffer_beg, buffer_end, '\0');

					if (null_pos != buffer_end)
					{
						_stream->seekg(_stream->tellg() - static_cast<std::streampos>(buffer_end - null_pos - 1));

						result += buffer;
						break;
					}
					else
					{
						result += std::string(buffer_beg, buffer_end);
					}
				}

				return result;
			}

		private:
			std::fstream *const _stream;
		};
	}

	coff_reader::coff_reader(const std::string &path) : _file(path, std::ios::in | std::ios::binary)
	{
		if (!_file.is_open())
		{
			return;
		}

		// Read file header
		_file.read(reinterpret_cast<char *>(&_header), sizeof(_header));
		_file.ignore(_header.optional_header_size);

		// Read section headers
		_sections.reserve(_header.num_sections);

		for (unsigned int i = 0; i < _header.num_sections; i++)
		{
			coff_section_header section = {};
			_file.read(reinterpret_cast<char *>(&section), sizeof(section));

			_sections.push_back({
				std::string(section.name, strnlen(section.name, sizeof(section.name))),
				section.raw_data_rva,
				section.data_size,
				section.relocation_table_rva,
				section.num_relocations
			});
		}

		// Verify file
		_is_valid = _file.good();
	}

	type_table coff_reader::types()
	{
		file_stream_reader stream(_file);

		// Find debug types section
		const auto section = std::find_if(_sections.begin(), _sections.end(), [](const content_section &it) { return it.name == ".debug$T"; });

		if (section == _sections.end() || section->data_rva == 0)
		{
			return type_table(0);
		}

		stream.seek(section->data_rva);

		// First 4 bytes indicate the CodeView version
		const auto codeview_version = stream.read<uint32_t>();

		if (codeview_version != 4)
		{
			return type_table(0);
		}

		// Create type table
		type_table types(0x1000 + section->data_size / 8); // approximation

		// A list of type records in CodeView format
		for (unsigned int current_index = 0x1000; stream.tell() < section->data_rva + section->data_size; current_index++)
		{
			// Each records starts with 2 bytes containing the size of the record after this element
			const auto size = stream.read<uint16_t>();
			// Next 2 bytes contain an enumeration depicting the type and format of the following data
			const auto tag = stream.read<uint16_t>();
			// The record is found by adding the current record size to the position of the previous size element
			const auto next = (stream.tell() - static_cast<std::streampos>(sizeof(uint16_t))) + size;

			switch (tag)
			{
				case 0x1504: // LF_CLASS
				case 0x1505: // LF_STRUCTURE
				{
					struct leaf_data
					{
						uint16_t element_count;
						uint16_t is_packed : 1;
						uint16_t has_constructors : 1;
						uint16_t has_overloaded_operators : 1;
						uint16_t is_nested : 1;
						uint16_t has_nested_types : 1;
						uint16_t has_overloaded_assignment : 1;
						uint16_t has_overloaded_casting : 1;
						uint16_t is_forward_reference : 1;
						uint16_t is_scoped : 1;
						uint16_t has_unique_name : 1;
						uint16_t is_sealed : 1;
						uint16_t hfa : 2;
						uint16_t is_intrinsic : 1;
						uint16_t mocom : 2;
						uint32_t field_descriptor_type_index;
						uint32_t derived_type_index;
						uint32_t vshape_table_type_index;
						uint16_t size;
					};

					const auto info = stream.read<leaf_data>();

					if (info.is_forward_reference || !info.has_unique_name)
					{
						break;
					}

					stream.read<std::string>();
					const auto unique_name = stream.read<std::string>();

					types.insert({ current_index, 0, std::move(unique_name) });
					break;
				}
				case 0x1506: // LF_UNION
				{
					struct leaf_data
					{
						uint16_t element_count;
						uint16_t is_packed : 1;
						uint16_t has_constructors : 1;
						uint16_t has_overloaded_operators : 1;
						uint16_t is_nested : 1;
						uint16_t has_nested_types : 1;
						uint16_t has_overloaded_assignment : 1;
						uint16_t has_overloaded_casting : 1;
						uint16_t is_forward_reference : 1;
						uint16_t is_scoped : 1;
						uint16_t has_unique_name : 1;
						uint16_t is_sealed : 1;
						uint16_t hfa : 2;
						uint16_t is_intrinsic : 1;
						uint16_t mocom : 2;
						uint32_t field_descriptor_type_index;
						uint16_t size;
					};

					const auto info = stream.read<leaf_data>();

					if (info.is_forward_reference || !info.has_unique_name)
					{
						break;
					}

					stream.read<std::string>();
					const auto unique_name = stream.read<std::string>();

					types.insert({ current_index, 0, std::move(unique_name) });
					break;
				}
				case 0x1507: // LF_ENUM
				{
					struct leaf_data
					{
						uint16_t element_count;
						uint16_t is_packed : 1;
						uint16_t has_constructors : 1;
						uint16_t has_overloaded_operators : 1;
						uint16_t is_nested : 1;
						uint16_t has_nested_types : 1;
						uint16_t has_overloaded_assignment : 1;
						uint16_t has_overloaded_casting : 1;
						uint16_t is_forward_reference : 1;
						uint16_t is_scoped : 1;
						uint16_t has_unique_name : 1;
						uint16_t is_sealed : 1;
						uint16_t hfa : 2;
						uint16_t is_intrinsic : 1;
						uint16_t mocom : 2;
						uint32_t base_type_index;
						uint32_t field_descriptor_type_index;
					};

					const auto info = stream.read<leaf_data>();

					if (info.is_forward_reference || !info.has_unique_name)
					{
						break;
					}

					stream.read<std::string>();
					const auto unique_name = stream.read<std::string>();

					types.insert({ current_index, info.base_type_index, std::move(unique_name) });
					break;
				}
				case 0x1515: // LF_TYPESERVER2
				{
					/*const auto guid = stream.read<struct guid>();
					const auto age = stream.read<uint32_t>();
					const auto path = stream.read<std::string>();*/
					break;
				}
				case 0x1601: // LF_FUNC_ID
				{
					/*const auto scope_id = stream.read<uint32_t>();
					const auto type_index = stream.read<uint32_t>();
					const auto name = stream.read<std::string>();*/
					break;
				}
				case 0x1602: // LF_MFUNC_ID
				{
					/*const auto parent_type_index = stream.read<uint32_t>();
					const auto type_index = stream.read<uint32_t>();
					const auto name = stream.read<std::string>();*/
					break;
				}
			}

			stream.seek(next);
		}

		return types;
	}
	std::unordered_map<std::string, ptrdiff_t> coff_reader::symbols()
	{
		file_stream_reader stream(_file);

		// Create symbol table
		std::unordered_map<std::string, ptrdiff_t> symbols;

		for (const auto &section : _sections)
		{
			// Find debug symbols sections
			if (section.name != ".debug$S" || section.data_rva == 0)
			{
				continue;
			}

			stream.seek(section.data_rva);

			// First 4 bytes indicate the CodeView version
			const auto codeview_version = stream.read<uint32_t>();

			if (codeview_version != 4)
			{
				continue;
			}

			while (stream.tell() < section.data_rva + section.data_size)
			{
				// Each subsection is aligned to 4-byte boundary
				const auto align = (stream.tell() - static_cast<std::streamsize>(section.data_rva)) % 4;

				if (align != 0)
				{
					stream.skip(4 - align);
				}

				// Read subsection header
				const auto signature = stream.read<uint32_t>();
				const auto subsection_size = stream.read<uint32_t>();

				// 241 = symbol subsection
				// 242 = line table
				// 243 = string table
				// 244 = file index to string table subsection
				if (signature != 241)
				{
					stream.skip(subsection_size);
					continue;
				}

				const auto subsection_end = stream.tell() + static_cast<std::streamsize>(subsection_size);

				// A list of symbol records in CodeView format
				while (stream.tell() < subsection_end)
				{
					// Each records starts with 2 bytes containing the size of the record after this element
					const auto size = stream.read<uint16_t>();
					// Next 2 bytes contain an enumeration depicting the symbol type and format of the following data
					const auto tag = stream.read<uint16_t>();
					// The next symbol record is found by adding the current record size to the position of the previous size element
					const auto next = (stream.tell() - static_cast<std::streampos>(sizeof(uint16_t))) + size;

					printf("%x\n", tag);

					switch (tag)
					{
						/*case 0x1101: // S_OBJNAME
						{
							//const auto signature = stream.read<uint32_t>();
							//const auto name = stream.read<std::string>();
							break;
						}
						case 0x1103: // S_BLOCK32
						{
							struct leaf_data
							{
								uint32_t parent, end;
								uint32_t length;
								uint32_t offset;
								uint16_t segment;
							};

							const auto info = stream.read<leaf_data>();
							const auto name = stream.read<std::string>();
							break;
						}
						case 0x113c: // S_COMPILE3
						{
							struct leaf_data
							{
								uint32_t language_index : 8;
								uint32_t has_ec : 1;
								uint32_t no_debug_info : 1;
								uint32_t has_link_time_code_generation : 1;
								uint32_t no_data_align : 1;
								uint32_t has_managed : 1;
								uint32_t has_security_checks : 1;
								uint32_t has_hotpatch : 1;
								uint32_t has_cvtcil : 1;
								uint32_t is_msil_module : 1;
								uint32_t has_sdl : 1;
								uint32_t has_pgo : 1;
								uint32_t has_exp_module : 1;
								uint32_t padding : 12;
								uint16_t machine;
								uint16_t frontend_version_major;
								uint16_t frontend_version_minor;
								uint16_t frontend_version_build;
								uint16_t frontend_version_qfe;
								uint16_t backend_version_major;
								uint16_t backend_version_minor;
								uint16_t backend_version_build;
								uint16_t backend_version_qfe;
							};

							const auto info = stream.read<leaf_data>();
							const auto compiler_string = stream.read<std::string>();
							break;
						}*/
						case 0x1146: // S_LPROC32_ID (begin local procedure)
						case 0x1147: // S_GPROC32_ID (begin global procedure)
						{
							struct leaf_data
							{
								uint32_t parent, end, next;
								uint32_t length;
								uint32_t debug_start_offset;
								uint32_t debug_end_offset;
								uint32_t type_index;
								uint32_t offset;
								uint16_t segment;
								uint8_t flags;
							};

							const auto info = stream.read<leaf_data>();
							const auto name = stream.read<std::string>();
							break;
						}
						/*case 0x1012: // S_FRAMEPROC
						{
							struct leaf_data
							{
								uint32_t frame_bytes;
								uint32_t padding_bytes;
								uint32_t padding_offset;
								uint32_t callee_save_register_bytes;
								uint32_t exception_handler_offset;
								uint16_t exception_handler_section_id;
								uint32_t flags;
							};
							break;
						}
						case 0x1108: // S_UDT
						{
							const auto type_index = stream.read<uint32_t>();
							const auto name = stream.read<std::string>();
							break;
						}
						case 0x1111: // S_REGREL32 (register relative address)
						{
							struct leaf_data
							{
								uint32_t offset;
								uint32_t type_index;
								uint16_t register_index;
							};

							const auto info = stream.read<leaf_data>();
							const auto name = stream.read<std::string>();
							break;
						}*/
						case 0x114f: // S_PROC_ID_END (end local/global procedure)
						{
							break;
						}
					}

					stream.seek(next);
				}
			}
		}

		return symbols;
	}
#if 0
	symbol_table coff_reader::symbols()
	{
		symbol_table symbols;
		file_stream_reader stream(_file);

		stream.seek(_header.symbol_table_rva);

		std::vector<std::pair<std::string, coff_symbol>> coffsymbols;
		coffsymbols.reserve(_header.num_symbols);

		for (uint i = 0; i < _header.num_symbols; i++)
		{
			const auto symbol = stream.read<coff_symbol>();
			std::string name = std::string(symbol.name, strnlen(symbol.name, 8));

			if (symbol.name_zeroes == 0)
			{
				const auto oldpos = stream.tell();
				stream.seek(_header.symbol_table_rva + _header.num_symbols * sizeof(coff_symbol) + symbol.name_offset);
				name = stream.read<std::string>();
				stream.seek(oldpos);
			}

			//symbols.insert({ name, 0, 0 });
			coffsymbols.push_back({ name, symbol });
		}

		for (const auto &section : _sections)
		{
			// Find code sections
			if (section.name.substr(0, 5) != ".text" || section.data_rva == 0 || section.relocation_table_rva == 0)
			{
				continue;
			}

			stream.seek(section.relocation_table_rva);

			for (uint i = 0; i < section.num_relocations; i++)
			{
				const auto relocation = stream.read<coff_relocation>();
				printf("");
			}
		}

		return symbols;
	}
#endif
}
