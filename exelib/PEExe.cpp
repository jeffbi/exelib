/// \file   PEExe.cpp
/// Implementation of PzExeInfo.
///
/// \author Jeff Bienstadt
///

#include <exception>
#include <istream>

#include "PEExe.h"
#include "readstream.h"

void PeExeInfo::load_image_file_header(std::istream &stream)
{
    read(stream, &_pe_image_file_header.signature);
    if (_pe_image_file_header.signature != PeImageFileHeader::pe_signature)
        throw std::runtime_error("not a PE executable file.");

    read(stream, &_pe_image_file_header.target_machine);
    read(stream, &_pe_image_file_header.num_sections);
    read(stream, &_pe_image_file_header.timestamp);
    read(stream, &_pe_image_file_header.symbol_table_offset);
    read(stream, &_pe_image_file_header.num_symbols);
    read(stream, &_pe_image_file_header.optional_header_size);
    read(stream, &_pe_image_file_header.characteristics);
}

void PeExeInfo::load_optional_header_base(std::istream &stream, PeOptionalHeaderBase &header)
{
    read(stream, &header.magic);
    read(stream, &header.linker_version_major);
    read(stream, &header.linker_version_minor);
    read(stream, &header.code_size);
    read(stream, &header.initialized_data_size);
    read(stream, &header.uninitialized_data_size);
    read(stream, &header.address_of_entry_point);
    read(stream, &header.base_of_code);
}

void PeExeInfo::load_optional_header_32(std::istream &stream)
{
    if (!_pe_optional_32)
        throw std::runtime_error("Cannot read into empty PE optional header (32-bit)");

    auto  &header = *_pe_optional_32;

    load_optional_header_base(stream, header);
    read(stream, &header.base_of_data);
    read(stream, &header.image_base);
    read(stream, &header.section_alignment);
    read(stream, &header.file_alignment);
    read(stream, &header.os_version_major);
    read(stream, &header.os_version_minor);
    read(stream, &header.image_version_major);
    read(stream, &header.image_version_minor);
    read(stream, &header.subsystem_version_major);
    read(stream, &header.subsystem_version_minor);
    read(stream, &header.win32_version_value);
    read(stream, &header.size_of_image);
    read(stream, &header.size_of_headers);
    read(stream, &header.checksum);
    read(stream, &header.subsystem);
    read(stream, &header.dll_characteristics);
    read(stream, &header.size_of_stack_reserve);
    read(stream, &header.size_of_stack_commit);
    read(stream, &header.size_of_heap_reserve);
    read(stream, &header.size_of_heap_commit);
    read(stream, &header.loader_flags);
    read(stream, &header.num_rva_and_sizes);
}

void PeExeInfo::load_optional_header_64(std::istream &stream)
{
    if (!_pe_optional_64)
        throw std::runtime_error("Cannot read into empty PE optional header (64-bit)");

    auto  &header = *_pe_optional_64;

    load_optional_header_base(stream, header);
    read(stream, &header.image_base);
    read(stream, &header.section_alignment);
    read(stream, &header.file_alignment);
    read(stream, &header.os_version_major);
    read(stream, &header.os_version_minor);
    read(stream, &header.image_version_major);
    read(stream, &header.image_version_minor);
    read(stream, &header.subsystem_version_major);
    read(stream, &header.subsystem_version_minor);
    read(stream, &header.win32_version_value);
    read(stream, &header.size_of_image);
    read(stream, &header.size_of_headers);
    read(stream, &header.checksum);
    read(stream, &header.subsystem);
    read(stream, &header.dll_characteristics);
    read(stream, &header.size_of_stack_reserve);
    read(stream, &header.size_of_stack_commit);
    read(stream, &header.size_of_heap_reserve);
    read(stream, &header.size_of_heap_commit);
    read(stream, &header.loader_flags);
    read(stream, &header.num_rva_and_sizes);
}
