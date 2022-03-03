/// \file   NEExe.cpp
/// Implementation of NzExeInfo.
///
/// \author Jeff Bienstadt
///

#include <exception>
#include <istream>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "NEExe.h"
#include "readers.h"
#include "resource_type.h"

namespace {

void load_seg_table_entry(std::istream &stream, NeSegmentEntry &entry, uint16_t align_shift, bool include_segment_data)
{
    read(stream, entry.sector);
    read(stream, entry.length);
    read(stream, entry.flags);
    read(stream, entry.min_alloc);

    if (include_segment_data)
    {
        if (entry.sector)   // zero means there is no sector data.
        {
            auto here = stream.tellg();
            stream.seekg(static_cast<std::streamsize>((entry.sector) << align_shift));
            std::streamsize size = entry.length ? entry.length : 65536;
            entry.data.resize(static_cast<size_t>(size));
            stream.read(reinterpret_cast<char *>(&entry.data[0]), size);
            stream.seekg(here);
        }
        entry.data_loaded = true;  // say we have data even if we didn't read anything.
    }
}

}   // anonymous namespace

void NeExeInfo::load_header(std::istream &stream)
{
    read(stream, _header.signature);
    if (_header.signature != NeExeHeader::ne_signature)
        throw std::runtime_error("not an NE executable file.");

    read(stream, _header.linker_version);
    read(stream, _header.linker_revision);
    read(stream, _header.entry_table_offset);
    read(stream, _header.entry_table_size);
    read(stream, _header.checksum);
    read(stream, _header.flags);
    read(stream, _header.auto_data_segment);
    read(stream, _header.inital_heap);
    read(stream, _header.initial_stack);
    read(stream, _header.initial_IP);
    read(stream, _header.initial_CS);
    read(stream, _header.initial_SP);
    read(stream, _header.initial_SS);
    read(stream, _header.num_segment_entries);
    read(stream, _header.num_module_entries);
    read(stream, _header.non_res_name_table_size);
    read(stream, _header.segment_table_offset);
    read(stream, _header.resource_table_offset);
    read(stream, _header.res_name_table_offset);
    read(stream, _header.module_table_offset);
    read(stream, _header.import_table_offset);
    read(stream, _header.non_res_name_table_pos);
    read(stream, _header.num_movable_entries);
    read(stream, _header.alignment_shift_count);
    read(stream, _header.num_resource_entries);
    read(stream, _header.executable_type);
    read(stream, _header.additional_flags);
    read(stream, _header.gangload_offset);
    read(stream, _header.gangload_size);
    read(stream, _header.min_code_swap_size);
    read(stream, _header.expected_win_version);
}

void NeExeInfo::load_entry_table(std::istream &stream)
{
    if (header().entry_table_size != 0)
    {
        _entry_table.resize(header().entry_table_size);
        stream.seekg(header_position() + header().entry_table_offset);
        stream.read(reinterpret_cast<char *>(&_entry_table[0]), header().entry_table_size);
    }
}

void NeExeInfo::load_segment_table(std::istream &stream, bool include_segment_data)
{
    if (header().num_segment_entries != 0)
    {
        auto alignment_shift = header().alignment_shift_count;
        if (alignment_shift == 0)
            alignment_shift = 9;

        _segment_table.resize(header().num_segment_entries);

        auto    table_location = header_position() + header().segment_table_offset;

        stream.seekg(table_location);
        for (uint16_t i = 0; i < header().num_segment_entries; ++i)
            load_seg_table_entry(stream, _segment_table[i], alignment_shift, include_segment_data);
    }
}

void NeExeInfo::load_resource_table(std::istream &stream, bool include_raw_data)
{
    // The resources count in the NE header often contains zero even when resources exist,
    // so we do the check this way. The table has an indicator for the final resource entry.
    if (header().resource_table_offset != header().res_name_table_offset)   // resources exist
    {
        auto    table_location = header_position() + header().resource_table_offset;

        stream.seekg(table_location);
        read(stream, _res_shift_count);    // read shift count

        _resource_table.clear();
        // read each resource
        while (true)
        {
            // read the resource type
            NeResourceEntry  entry;
            read(stream, entry.type);
            if (entry.type == 0) // marks last resource entry
                break;
            read(stream, entry.count);
            read(stream, entry.reserved);

            // read the information for each resource of this type
            for (uint8_t i=0; i < entry.count; ++i)
            {
                NeResource  resource;
                read(stream, resource.offset);
                read(stream, resource.length);
                read(stream, resource.flags);
                read(stream, resource.id);
                read(stream, resource.reserved);
                entry.resources.push_back(resource);
            }

            _resource_table.push_back(entry);
        }

        // now read the resource names
        char name_buffer[256];
        uint8_t string_size;
        for (auto &&entry : _resource_table)
        {
            // for each resource type there is either a name or it is a pre-defined, integer type
            if (!(entry.type & 0x8000)) // This is a named resource type
            {
                // here, the type is an offset to the resource name, relative to the start of resource table.
                stream.seekg(table_location + entry.type);
                read(stream, string_size);
                stream.read(name_buffer, string_size);
                entry.type_name.append(name_buffer, string_size);
            }

            // read the resource name and the content for each resource of this type
            for (auto &&resource : entry.resources)
            {
                if (!(resource.id & 0x8000))    // here also, high bit indicates an integer resource.
                {
                    stream.seekg(table_location + resource.id);
                    read(stream, string_size);
                    stream.read(name_buffer, string_size);
                    resource.name.append(name_buffer, string_size);
                }

                if (include_raw_data)
                {
                    // read the raw content of the resource
                    std::streamoff  offset{resource.offset << _res_shift_count};
                    size_t          length{static_cast<unsigned>(resource.length) << _res_shift_count};

                    if (length)
                    {
                        resource.bits.resize(length);
                        stream.seekg(offset);
                        stream.read(reinterpret_cast<char *>(&resource.bits[0]), static_cast<std::streamsize>(resource.bits.size()));
                    }
                    resource.data_loaded = true;
                }
                else
                {
                    resource.data_loaded = false;
                }
            }
        }
    }
}

void NeExeInfo::load_resident_name_table(std::istream &stream)
{
    auto    table_location{header_position() + header().res_name_table_offset};
    uint8_t string_size;
    char    name_buffer[256];

    stream.seekg(table_location);
    read(stream, string_size);

    while (string_size)
    {
        stream.read(name_buffer, string_size);
        NeName name;
        name.name.append(name_buffer, string_size);
        read(stream, name.ordinal);
        _resident_names.push_back(name);

        read(stream, string_size);
    }
}

void NeExeInfo::load_nonresident_name_table(std::istream &stream)
{
    auto    table_location = header().non_res_name_table_pos;     // This one is relative to the beginning of the file.
    uint8_t string_size;
    char    name_buffer[256];

    stream.seekg(table_location);
    read(stream, string_size);

    while (string_size)
    {
        stream.read(name_buffer, string_size);
        NeName name;
        name.name.append(name_buffer, string_size);
        read(stream, name.ordinal);
        _nonresident_names.push_back(name);

        read(stream, string_size);
    }
}

void NeExeInfo::load_imported_name_table(std::istream &stream)
{
    auto    entry_table_location = header_position() + header().entry_table_offset;
    auto    table_location = header_position() + header().import_table_offset;
    auto    table_size = entry_table_location - table_location;
    auto    pos = 0u;
    char    name_buffer[256] {0};

    stream.seekg(table_location);
    while (pos < table_size)
    {
        uint8_t string_size;
        read(stream, string_size);
        ++pos;
        if (string_size)
        {
            stream.read(name_buffer, string_size);
            pos += string_size;
        }
        else
        {
            name_buffer[0] = '\0';
        }
        _imported_names.emplace_back(name_buffer, string_size);
    }
}

void NeExeInfo::load_module_name_table(std::istream &stream)
{
    if (header().num_module_entries)
    {
        std::streamoff          table_location{header_position() + header().module_table_offset};
        std::vector<uint16_t>   mod_offsets(header().num_module_entries);

        // load up all the module-name offsets
        stream.seekg(table_location);
        stream.read(reinterpret_cast<char *>(&mod_offsets[0]), static_cast<std::streamsize>(mod_offsets.size() * sizeof(mod_offsets[0])));

        // point to the imported names table
        table_location = header_position() + header().import_table_offset;
        uint8_t string_size;
        char    name_buffer[256];
        for (uint16_t offset : mod_offsets)
        {
            stream.seekg(table_location + offset);
            read(stream, string_size);
            stream.read(name_buffer, string_size);
            _module_names.emplace_back(name_buffer, string_size);
        }
    }
}
