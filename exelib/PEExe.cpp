/// \file   PEExe.cpp
/// Implementation of PzExeInfo.
/// 
/// \author Jeff Bienstadt
///

#include <istream>
#include <memory>

#include "PEExe.h"
#include "readstream.h"

void PeExeInfo::load_header(std::istream &stream)
{
    read(stream, &_pe_header.signature);
    if (_pe_header.signature != PeExeHeader::pe_signature)
        throw std::runtime_error("not a PE executable file.");

    read(stream, &_pe_header.target_machine);
    read(stream, &_pe_header.num_sections);
    read(stream, &_pe_header.timestamp);
    read(stream, &_pe_header.symbol_table_offset);
    read(stream, &_pe_header.num_symbols);
    read(stream, &_pe_header.optional_header_size);
    read(stream, &_pe_header.characteristics);
}
