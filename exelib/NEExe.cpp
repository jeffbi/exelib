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
#include "ReadStream.h"
#include "resource_type.h"

namespace {

void load_seg_table_entry(std::istream &stream, NeSegmentEntry &entry)
{
    read(stream, &entry.sector);
    read(stream, &entry.length);
    read(stream, &entry.flags);
    read(stream, &entry.min_alloc);
}

//TODO: move this to a common location?
std::string make_resource_type_name(uint16_t type)
{
    static std::unordered_map<uint16_t, const char *> predefined_resource_names =
        {
            {static_cast<uint16_t>(ResourceType::Cursor), "CURSOR"},
            {static_cast<uint16_t>(ResourceType::Bitmap), "BITMAP"},
            {static_cast<uint16_t>(ResourceType::Icon), "ICON"},
            {static_cast<uint16_t>(ResourceType::Menu), "MENU"},
            {static_cast<uint16_t>(ResourceType::Dialog), "DIALOG"},
            {static_cast<uint16_t>(ResourceType::String), "STRING"},
            {static_cast<uint16_t>(ResourceType::FontDir), "FONTDIR"},
            {static_cast<uint16_t>(ResourceType::Font), "FONT"},
            {static_cast<uint16_t>(ResourceType::Accelerator), "ACCELERAOR"},
            {static_cast<uint16_t>(ResourceType::RCData), "RCDATA"},
            {static_cast<uint16_t>(ResourceType::MessageTable), "MESSAGE_TABLE"},
            {static_cast<uint16_t>(ResourceType::GroupCursor), "GROUP_CURSOR"},
            {static_cast<uint16_t>(ResourceType::GroupIcon), "GROUP_ICON"},

            {static_cast<uint16_t>(ResourceType::Version), "VERSION"},
            {static_cast<uint16_t>(ResourceType::DlgInclude), "DLGINCLUDE"},
            {static_cast<uint16_t>(ResourceType::PlugPlay), "PLUGPLAY"},
            {static_cast<uint16_t>(ResourceType::VXD), "VXD"},
            {static_cast<uint16_t>(ResourceType::AniCursor), "ANICURSOR"},
            {static_cast<uint16_t>(ResourceType::AniIcon), "ANIICON"},
            {static_cast<uint16_t>(ResourceType::HTML), "HTML"},
        };

    if (type & 0x8000)
    {
        type &= ~0x8000;
        auto it = predefined_resource_names.find(type);
        if (it == predefined_resource_names.end())
            return "<UNKNOWN>";
        else
            return it->second;
    }
    else
    {
        return "";  // this should ever happen because this function should never be called without the high bit set
                    //TODO: consider throwing an error instead
    }
}

}   // anonymous namespace

void NeExeInfo::load_header(std::istream &stream)
{
    read(stream, &_header.signature);
    if (_header.signature != NeExeHeader::ne_signature)
        throw std::runtime_error("not an NE executable file.");

    read(stream, &_header.linker_version);
    read(stream, &_header.linker_revision);
    read(stream, &_header.entry_table_offset);
    read(stream, &_header.entry_table_size);
    read(stream, &_header.checksum);
    read(stream, &_header.flags);
    read(stream, &_header.auto_data_segment);
    read(stream, &_header.inital_heap);
    read(stream, &_header.initial_stack);
    read(stream, &_header.initial_IP);
    read(stream, &_header.initial_CS);
    read(stream, &_header.initial_SP);
    read(stream, &_header.initial_SS);
    read(stream, &_header.num_segment_entries);
    read(stream, &_header.num_module_entries);
    read(stream, &_header.non_res_name_table_size);
    read(stream, &_header.segment_table_offset);
    read(stream, &_header.resource_table_offset);
    read(stream, &_header.res_name_table_offset);
    read(stream, &_header.module_table_offset);
    read(stream, &_header.import_table_offset);
    read(stream, &_header.non_res_name_table_pos);
    read(stream, &_header.num_movable_entries);
    read(stream, &_header.alignment_shift_count);
    read(stream, &_header.num_resource_entries);
    read(stream, &_header.executable_type);
    read(stream, &_header.additional_flags);
    read(stream, &_header.gangload_offset);
    read(stream, &_header.gangload_size);
    read(stream, &_header.min_code_swap_size);
    read(stream, &_header.expected_win_version);
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

void NeExeInfo::load_segment_table(std::istream &stream)
{
    if (header().num_segment_entries != 0)
    {
        _segment_table.resize(header().num_segment_entries);

        auto    table_location = header_position() + header().segment_table_offset;

        stream.seekg(table_location);
        for (int i=0; i < header().num_segment_entries; ++i)
            load_seg_table_entry(stream, _segment_table[i]);
    }
}

void NeExeInfo::load_resource_table(std::istream &stream)
{
    // The resources count in the NE header often contains zero even when resources exist,
    // so we do the check this way. The table has an indicator for the final resource entry.
    if (header().resource_table_offset != header().res_name_table_offset)   // resources exist
    {
        auto    table_location = header_position() + header().resource_table_offset;

        stream.seekg(table_location);
        read(stream, &_res_shift_count);    // read shift count

        _resource_table.clear();
        // read each resource
        while (true)
        {
            // read the resource type
            NeResource  resource;
            read(stream, &resource.type);
            if (resource.type == 0) // marks last resource entry
                break;
            read(stream, &resource.count);
            read(stream, &resource.reserved);

            // read the information for each resource of this type
            for (uint8_t i=0; i < resource.count; ++i)
            {
                NeResourceInfo  info;
                read(stream, &info.offset);
                read(stream, &info.length);
                read(stream, &info.flags);
                read(stream, &info.id);
                read(stream, &info.reserved);
                resource.info.push_back(info);
            }

            _resource_table.push_back(resource);
        }

        // now read the resource names
        char name_buffer[256];
        uint8_t string_size;
        for (auto &&resource : _resource_table)
        {
            // for each resource type there is either a name or it is a pre-defined, integer type
            if (resource.type & 0x8000) // high bit set indicates integer type
            {
                resource.type_name = make_resource_type_name(resource.type);
            }
            else    // This is a named resource type
            {
                // here, the type is an offset to the resource name, relative to the start of resource table.
                stream.seekg(table_location + resource.type);
                read(stream, &string_size);
                stream.read(name_buffer, string_size);
                resource.type_name.append(name_buffer, string_size);
            }

            // read the resource name and the content for each resource of this type
            for (auto &&info : resource.info)
            {
                if (info.id & 0x8000)   // here also, high bit indicates an integer resource.
                {
                    info.name = '#' + std::to_string(info.id & ~0x8000);
                }
                else    // This is a named resource
                {
                    stream.seekg(table_location + info.id);
                    read(stream, &string_size);
                    stream.read(name_buffer, string_size);
                    info.name.append(name_buffer, string_size);
                }

                // read the raw content of the resource
                auto offset = info.offset << _res_shift_count;
                auto length = info.length << _res_shift_count;

                if (length)
                {
                    info.bits.resize(length);
                    stream.seekg(offset);
                    stream.read(reinterpret_cast<char *>(&info.bits[0]), info.bits.size());
                }
            }
        }
    }
}

void NeExeInfo::load_resident_name_table(std::istream &stream)
{
    auto    table_location = header_position() + header().res_name_table_offset;
    uint8_t string_size;
    char    name_buffer[256];

    stream.seekg(table_location);
    read(stream, &string_size);

    while (string_size)
    {
        stream.read(name_buffer, string_size);
        NeName name;
        name.name.append(name_buffer, string_size);
        read(stream, &name.ordinal);
        _resident_names.push_back(name);

        read(stream, &string_size);
    }
}

void NeExeInfo::load_nonresident_name_table(std::istream &stream)
{
    auto    table_location = header().non_res_name_table_pos;     // This one is relative to the beginning of the file.
    uint8_t string_size;
    char    name_buffer[256];

    stream.seekg(table_location);
    read(stream, &string_size);

    while (string_size)
    {
        stream.read(name_buffer, string_size);
        NeName name;
        name.name.append(name_buffer, string_size);
        read(stream, &name.ordinal);
        _nonresident_names.push_back(name);

        read(stream, &string_size);
    }
}

void NeExeInfo::load_imported_name_table(std::istream &stream)
{
    auto    table_location = header_position() + header().import_table_offset;
    uint8_t string_size;
    char    name_buffer[256];

    stream.seekg(table_location);
    read(stream, &string_size);
    while (string_size)
    {
        stream.read(name_buffer, string_size);
        _imported_names.push_back(std::string(name_buffer, string_size));
        read(stream, &string_size);
    }
}

void NeExeInfo::load_module_name_table(std::istream &stream)
{
    if (header().num_module_entries)
    {
        auto                    table_location = header_position() + header().module_table_offset;
        std::vector<uint16_t>   mod_offsets(header().num_module_entries);

        // load up all the module-name offsets
        stream.seekg(table_location);
        stream.read(reinterpret_cast<char *>(&mod_offsets[0]), mod_offsets.size() * sizeof(mod_offsets[0]));

        // point to the imported names table
        table_location = header_position() + header().import_table_offset;
        uint8_t string_size;
        char    name_buffer[256];
        for (uint16_t offset : mod_offsets)
        {
            stream.seekg(table_location + offset);
            read(stream, &string_size);
            stream.read(name_buffer, string_size);
            _module_names.emplace_back(name_buffer, string_size);
        }
    }
}
