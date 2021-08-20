/// \file   PEExe.cpp
/// Implementation of PzExeInfo.
///
/// \author Jeff Bienstadt
///

#include <algorithm>
#include <exception>
#include <istream>

#include "LoadOptions.h"
#include "PEExe.h"
#include "readstream.h"

PeExeInfo::PeExeInfo(std::istream &stream, size_t header_location, LoadOptions::Options options)
    : _header_position{header_location}
{
    load_image_file_header(stream);

    if (_pe_image_file_header.optional_header_size != 0)    // should be zero only for object files, never for image files.
    {
        uint32_t nRVAs = 0;

        uint16_t magic;
        read(stream, &magic);
        stream.seekg(-static_cast<int>(sizeof(magic)), std::ios::cur);

        if (magic == 0x010B)        // 32-bit optional header
        {
            _pe_optional_32 = std::make_unique<PeOptionalHeader32>();
            load_optional_header_32(stream);
            nRVAs = _pe_optional_32->num_rva_and_sizes;
        }
        else if (magic == 0x020B)   // 64-bit optional header
        {
            _pe_optional_64 = std::make_unique<PeOptionalHeader64>();
            load_optional_header_64(stream);
            nRVAs = _pe_optional_64->num_rva_and_sizes;
        }
        else                        // unrecognized optional header type
        {
            //TODO: Indicate an error? Throw?
        }

        // Load the Data Directory
        _pe_data_directory.reserve(nRVAs);
        for (uint32_t i = 0; i < nRVAs; ++i)
        {
            PeDataDirectoryEntry entry;
            read(stream, &entry.virtual_address);
            read(stream, &entry.size);

            _pe_data_directory.push_back(entry);
        }

        // Load the sections; headers and optionally raw data
        _pe_sections.reserve(_pe_image_file_header.num_sections);
        for (uint16_t i = 0; i < _pe_image_file_header.num_sections; ++i)
        {
            // load the section header
            PeSectionHeader header;

            stream.read(reinterpret_cast<char *>(&header.name), (sizeof(header.name) / sizeof(header.name[0])));
            read(stream, &header.virtual_size);
            read(stream, &header.virtual_address);
            read(stream, &header.size_of_raw_data);
            read(stream, &header.raw_data_position);
            read(stream, &header.relocations_position);
            read(stream, &header.line_numbers_position);
            read(stream, &header.number_of_relocations);
            read(stream, &header.number_of_line_numbers);
            read(stream, &header.characteristics);

            if (options & LoadOptions::LoadSectionData)
            {
                std::vector<uint8_t>    data;
                auto data_size = std::min(header.virtual_size, header.size_of_raw_data);
                if (data_size)
                {
                    data.resize(data_size);
                    auto here = stream.tellg();
                    stream.seekg(header.raw_data_position);
                    stream.read(reinterpret_cast<char *>(&data[0]), data_size);
                    stream.seekg(here);
                }

                _pe_sections.emplace_back(header, std::move(data));
            }
            else
            {
                _pe_sections.emplace_back(header);
            }
        }
        //TODO: Load more here!!!
    }
    else
    {
        throw std::runtime_error("Not a PE executable file. Perhaps a COFF object file?");
    }
}

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
