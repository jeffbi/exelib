/// \file   ReadStream.h
/// Provides a elper function to read binary data from a stream
/// without having to have repeated reinterpre_casts scattered
/// throughout the code.
/// 
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_READSTREAM_H_
#define _EXELIB_READSTREAM_H_

#include <istream>

template<typename T>
size_t read(std::istream &stream, T *destination)
{
    stream.read(reinterpret_cast<char *>(destination), sizeof(T));

    return sizeof(T);
}

#endif  //_EXELIB_READSTREAM_H_
