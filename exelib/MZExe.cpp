/// \file   MZExe.cpp
/// Implementation of MzExeInfo.
/// 
/// \author Jeff Bienstadt
///

#include <cstring>      // for memset
#include <exception>
#include <istream>
#include <vector>

#include "MZExe.h"
#include "ReadStream.h"

/// \brief  Load the old MZ header from a stream. All EXE-type
///         files begin with this header, including resource-only files.
/// \param stream   Input stream from which to read.
void MzExeInfo::load_header(std::istream &stream)
{
    read(stream, &_header.signature);
    if (_header.signature != MzExeHeader::mz_signature)
        throw std::runtime_error("not a MZ executable file.");

    read(stream, &_header.bytes_on_last_page);
    read(stream, &_header.num_pages);
    read(stream, &_header.num_relocation_items);
    read(stream, &_header.header_size);
    read(stream, &_header.min_allocation);
    read(stream, &_header.requested_allocation);
    read(stream, &_header.initial_SS);
    read(stream, &_header.initial_SP);
    read(stream, &_header.checksum);
    read(stream, &_header.initial_IP);
    read(stream, &_header.initial_CS);
    read(stream, &_header.relocation_table_pos);
    read(stream, &_header.overlay);
    if (_header.relocation_table_pos == 0x40)
    {
        read(stream, &_header.reserved);
        read(stream, &_header.new_header_offset);
    }
    else    // This is an OLD exe file. Nothing after the old exe header is useful.
    {
        memset(_header.reserved, 0, sizeof(_header.reserved));
        _header.new_header_offset = 0;
    }
}

/// \brief  Load the relocation table for the old MZ-style executable.
/// \param stream   Stream from which to read.
/// \param location Offset from the beginning of the file to the relocation table.
/// \param count    Number of entries in the relocation table
void MzExeInfo::load_relocation_table(std::istream &stream, uint16_t location, uint16_t count)
{
    _relocation_table.clear();

    if (count)
    {
        _relocation_table.resize(count);
        stream.seekg(location);

        for (uint16_t i = 0; i < count; ++i)
        {
            MzRelocPointer  reloc;

            read(stream, &reloc.offset);
            read(stream, &reloc.segment);

            _relocation_table[i] = reloc;
        }
    }
}