#pragma once

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>

class filewatcher;

extern void print(const char *message, size_t length);
inline void print(const std::string &message)
{
	print(message.data(), message.size());
}

namespace jetlink
{
	class application
	{
	public:
		application();
		~application();

		void run();
		bool link(const std::string &path);

	private:
		uint8_t *_imagebase = nullptr;
		std::vector<std::string> _sourcefiles;
		std::unordered_map<std::string, void *> _symbols;
		std::unique_ptr<filewatcher> _filewatcher;
		std::string _source_dir, _compiled_module_file;
		bool _initialized, _executing;
		void *_compiler_stdin, *_compiler_stdout;
	};
}
