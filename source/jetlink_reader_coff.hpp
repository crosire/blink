#pragma once

#include "jetlink_symbols.hpp"
#include "jetlink_reader_pdb.hpp"

namespace jetlink
{
	/// <summary>
	/// Class which reads a raw COFF file.
	/// </summary>
	class coff_reader
	{
	public:
		/// <summary>
		/// Opens a COFF file.
		/// </summary>
		/// <param name="path">The file system path the COFF file is located at.</param>
		explicit coff_reader(const std::string &path);

		/// <summary>
		/// Returns whether this PDB file exists and is of a valid format.
		/// </summary>
		bool is_valid() const
		{
			return _is_valid;
		}

		/// <summary>
		/// Walks through all types in this COFF object file and returns them.
		/// </summary>
		type_table types();
		/// <summary>
		/// Walks through all symbols in this COFF object file and returns them.
		/// </summary>
		std::unordered_map<std::string, ptrdiff_t> symbols();

	private:
		struct file_header
		{
			uint16_t machine;
			uint16_t num_sections;
			uint32_t timestamp;
			uint32_t symbol_table_rva;
			uint32_t num_symbols;
			uint16_t optional_header_size;
			uint16_t flags;
		};
		struct content_section
		{
			std::string name;
			uint32_t data_rva, data_size;
			uint32_t relocation_table_rva, num_relocations;
		};

		std::fstream _file;
		bool _is_valid = false;
		file_header _header = {};
		std::vector<content_section> _sections;
	};
}
