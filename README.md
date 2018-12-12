blink
=====

A tool that lets you edit the source code of a Windows C++ application live, while it is running, without having to go through the usual compile-and-restart cycle. It is effectivly a runtime linker that detects changes to source code files, compiles them and links them back into the running application, while overwriting the previous image.

In contrast to similar projects, **blink does not require you to modify your C++ project in any way**. In fact it works on all applications as long as they were compiled with debug symbols (so that a PDB file is created) and you have their source code somewhere on your system.

![Demo](https://i.imgur.com/sUu3asj.gif)

## Usage

There are two ways to use blink:
1) Either launch your application via blink:\
	```blink.exe foo.exe -arguments```
2) Or attach blink to an already running application:\
	```blink.exe PID``` where PID is the process ID to attach to

## Contributing

Any contributions to the project are welcomed, it's recommended to use GitHub [pull requests](https://help.github.com/articles/using-pull-requests/).

## License

All the source code is licensed under the conditions of the [BSD 2-clause license](LICENSE.md).
