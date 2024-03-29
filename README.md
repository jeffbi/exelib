# exelib
`exelib` is a C++ library for reading EXE-format executables.

## Why?
I wrote this primarily as an exercise, and as a tool to extract `.fnt` files
from `.fon` files (yes, `.fon` file are EXE  executable files with a different
extension, and they are still in use even on Windows 10). I hope that others
might find the library and/or the samples useful.

## A Quick Overview of EXE Executables
(You can skip this part if you're already familiar with the format of EXE executables.)

All EXE executables begin with the letters MZ. This is a "signature" indicating the
beginning of a header structure describing the executable. They are also the initials
of Mark Zbikowski, one of the architects of MS-DOS.

Around the time Windows 1.0 came about, additional information was added to the EXE file,
including a new header starting with the letters NE. The MZ header was extended to
include an offset to this section of the file.

When Windows NT was released another new section of the EXE file came to be, replacing
the NE section. This section makes the EXE a Portable Executable and begins with
the letters PE.

There is another executable type known as Linear Executable with its own extended
format. These are used for things like OS/2 2.0 executables and VxD drivers.
The new section for Linear Executables begins with the letters LE or LX.
`exelib` recognizes these executable types but does not yet support them.

## Using the Library
The simplest way to use the library is to construct an `ExeInfo` object,
passing a `std::istream` or any of its derived classes such as `std::ifstream`.
The stream must be created using binary mode. For example:
```c++
    std::ifstream fs("fred.exe", std::ios::binary);
    ExeInfo info(fs);
```
This will load the information about the executable into the `info` object.

The `ExeInfo` object has functions to provide the executable type as well as
access to the different headers, if they exist. Access to the MZ section is
guaranteed. The executable may or may not contain any of the new sections,
and there will be only zero or one extended section in the file.

The library contains documentation comments so you can run `doxygen` on the
sources to generate documentation.

> Note: EXE/PE executables store their values in little-endian, as used on
> Intel processors among others. The code in this library is written for
> little-endian processors and does not automatically convert to big-endian.

## State of the Library
The library is currently able to load information from old MZ and from NE-style
executables. It is also able to load quite a bit of the data in a PE file,
including any CLI (.NET) metadata. More work on PE executables is underway
now and should be available in the near future.

## The Samples
There are three sample programs provided, `exedump`, `fntextract`, and `ExeXamine`.

### `exedump`
The `exedump` sample dumps information about the executable to `stdout`.
It displays headers and other more detailed information about the executable.

### `fntextract`
The `fntextract` sample extracts `.fnt` font data from a `.fon` file, and writes
it to `.fnt` files. This sample is essentially the tool that was the impetus behind
the library, and accomplishes its task in just about 100 lines of code.

### `ExeXamine`
The `ExeXamine` sample is a native Windows application written in C++ using the
Win32 SDK. This is a fairly simple application allowing the perusal of executables
using the Windows GUI.

## Project and Sources
The C++ sources for the library and samples are provided. Make files and Windows
Visual Studio solutions can be generated by CMake.

The library and two of the the samples are cross-platform and have been tested on
Windows and on Linux. Why Linux? The .NET system can be installed on Linux, and
executable files---DLLs usually---built for .NET use the PE executable type.

The third sample, ExeXamine, is a Windows-only native application and is not
cross-platform.

### C++ Standards
The library and samples are written using portable Modern C++.
The library itself and the `fntextract` sample both compile with C++14
or higher. The `exedump` sample uses some features of C++ 17.

## License
The library and samples are released under the MIT license. See the file LICENSE.txt
for more detail.
