#pragma once

#include <string>
#include <vector>

namespace jetlink
{
	struct type
	{
		unsigned int index, base_type_index;
		std::string mangled_name;
		size_t size;
		unsigned char is_builtin : 1, is_const : 1, is_volatile : 1, is_unaligned : 1, is_array : 1, is_pointer : 1, is_function : 1, is_forward_reference : 1;
	};

	class type_table
	{
	public:
		type_table(size_t capacity) : _types(capacity)
		{
		}

		void insert(const type &type)
		{
			_types[type.index] = type;
		}

		type &resolve(unsigned int index)
		{
			return _types[index];
		}
		const type &resolve(unsigned int index) const
		{
			return _types[index];
		}

	private:
		std::vector<type> _types;
	};
}
