/// \file   nedump.cpp
/// Implementation of the function to dump a new NE-style executable.
///
/// \author Jeff Bienstadt
///

#include <iomanip>
#include <ostream>
#include <string>
#include <sstream>
#include <unordered_map>

#include <NEExe.h>
#include <resource_type.h>

#include "HexVal.h"

namespace {

/////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////

// Helper for dumping a collection of NeName items
size_t dump_ne_names(const NeExeInfo::NameContainer &names, std::ostream &outstream)
{
    if (names.size())
    {
        outstream << "Ordinal  Name\n"
                  << "-------  ----\n";

        for (const auto &name : names)
            outstream << " 0x" << HexVal{name.ordinal} << "  " << name.name << '\n';
    }

    return names.size();
}

// Helper for dumping a collection of strings
size_t dump_strings(const NeExeInfo::StringContainer &strings, std::ostream &outstream, bool show_length)
{
    if (strings.size())
    {
        if (show_length)
            outstream << "Length  Name\n"
                      << "------  ----\n";

        for (const auto &str : strings)
        {
            if (show_length)
                outstream << std::setw(6) << str.size() << "  ";
            outstream << str << '\n';
        }
    }

    return strings.size();
}

const std::string get_exe_target(uint8_t type)
{
    switch (type)
    {
        case static_cast<uint8_t>(NeExeType::Unknown):
            return "Unknown";
        case static_cast<uint8_t>(NeExeType::OS_2):
            return "OS/2";
        case static_cast<uint8_t>(NeExeType::Windows):
            return "Windows";
        case static_cast<uint8_t>(NeExeType::EuroDOS4):
            return "European MS-DOS 4.x";
        case static_cast<uint8_t>(NeExeType::Windows386):
            return "Windows 386";
        case static_cast<uint8_t>(NeExeType::BOSS):
            return "BOSS";
        case static_cast<uint8_t>(NeExeType::PharLap_OS2):
            return "PharLap 286|DOS-Extender, OS/2";
        case static_cast<uint8_t>(NeExeType::PharLap_Win):
            return "PharLap 286|DOS-Extender, Windows";
        default:
        {
            std::stringstream ss;

            ss << "0x" << HexVal{type};

            return ss.str();
        }
    }
}


////////////////////////////////////////////////////
// Functions for dumping individual NE areas
////////////////////////////////////////////////////

void dump_header(const NeExeInfo &info, std::ostream &outstream)
{
    outstream << "New NE header\n-------------------------------------------\n";

    const NeExeHeader &header = info.header();

    outstream << (header.flags & 0x8000 ? "Library:" : "Module: ") << "                            " << info.module_name() << '\n';
    outstream << "Description:                        " << info.module_description() << '\n';

    //if (header.executable_type == static_cast<uint8_t>(NeExeType::Windows))
        outstream << "Expected Windows version:           "
                  << static_cast<unsigned>((header.expected_win_version >> 8) & 0xFF) << '.'
                  << static_cast<unsigned>(header.expected_win_version & 0xFF) << "\n\n";

    outstream << "Signature:                            0x" << HexVal{header.signature} << '\n';
    outstream << "Linker version:                          " << std::setw(3) << static_cast<unsigned>(header.linker_version) << '\n';
    outstream << "Linker revision:                         " << std::setw(3) << static_cast<unsigned>(header.linker_revision) << '\n';
    outstream << "Entry Table offset:                   0x" << HexVal{header.entry_table_offset} << '\n';
    outstream << "Entry Table size (bytes):              " << std::setw(5) << header.entry_table_size << '\n';
    outstream << "Checksum:                         0x" << HexVal{header.checksum} << '\n';
    outstream << "Flags:                                0x" << HexVal{header.flags} << '\n';
    outstream << "Automatic Data Segment:               0x" << HexVal{header.auto_data_segment} << '\n';
    outstream << "Heap size:                            0x" << HexVal{header.inital_heap} << '\n';
    outstream << "Initial SS:                           0x" << HexVal{header.initial_SS} << '\n';
    outstream << "Initial SP:                           0x" << HexVal{header.initial_SP} << '\n';
    outstream << "Initial CS:                           0x" << HexVal{header.initial_CS} << '\n';
    outstream << "Initial IP:                           0x" << HexVal{header.initial_IP} << '\n';
    outstream << "Entries in Segment Table:              " << std::setw(5) << header.num_segment_entries << '\n';
    outstream << "Entries in Module Table:               " << std::setw(5) << header.num_module_entries << '\n';
    outstream << "Non-resident Name Table size (bytes):  " << std::setw(5) << header.non_res_name_table_size << '\n';
    outstream << "Segment Table offset:                 0x" << HexVal{header.segment_table_offset} << '\n';
    outstream << "Resource Table offset:                0x" << HexVal{header.resource_table_offset} << '\n';
    outstream << "Resident Name Table offset:           0x" << HexVal{header.res_name_table_offset} << '\n';
    outstream << "Module Table offset:                  0x" << HexVal{header.module_table_offset} << '\n';
    outstream << "Import Table offset:                  0x" << HexVal{header.import_table_offset} << '\n';
    outstream << "Non-resident Name Table position: 0x" << HexVal{header.non_res_name_table_pos} << '\n';
    outstream << "Number of movable entries:             " << std::setw(5) << header.num_movable_entries << '\n';
    outstream << "Alignment shift count:                 " << std::setw(5) << header.alignment_shift_count << '\n';
    outstream << "Number of Resource Table entries:      " << std::setw(5) << header.num_resource_entries << '\n';
    outstream << "Executable Type:                        0x" << HexVal{header.executable_type} << ' ' << get_exe_target(header.executable_type) << '\n';
    outstream << "Additional Flags:                       0x" << HexVal{header.additional_flags} << '\n';
    outstream << "Gangload offset:                      0x" << HexVal{header.gangload_offset} << '\n';
    outstream << "Gangload size:                        0x" << HexVal{header.gangload_size} << '\n';
    outstream << "Minimum code swap size:                " << std::setw(5) << header.min_code_swap_size << '\n';
}

// This version of dump_entry_table demonstrates how to extract Entry Tabel information
// from the raw bytes read from the file, and requires some intimate knowlege of what
// the entry table looks like and how it works.
//
// You may prefer to use the version of dump_entry_table that uses pre-parsed objects,
// implemented below this function.
void dump_entry_table(const NeExeInfo::ByteContainer &table, std::ostream &outstream)
{
    size_t  bundle_count = 0;
    outstream << "Entry Table\n-------------------------------------------\n";
    if (table.size())
    {
        const auto *ptr{table.data()};
        uint16_t    ordinal{1};

        while (true)
        {
            uint8_t n_bundle{*ptr++};   // number of entries in this bundle
            if (n_bundle == 0)
                break;  // end of entry table;

            ++bundle_count;
            outstream << "Bundle " << bundle_count << ", " << static_cast<unsigned int>(n_bundle) << " entries\n";

            uint8_t indicator{*ptr++};

            if (indicator == 0x00)      // empty bundle
            {
                outstream << "(empty bundle)\n";
                ++ordinal;
            }
            else if (indicator == 0xFF) // MOVEABLE segments
            {
                for (uint8_t i = 0; i < n_bundle; ++i)
                {
                    uint8_t     flags{*ptr++};
                    ptr += sizeof(uint16_t);    // Skip over the INT 3F instruction bytes. we don't display them
                    uint8_t     segment{*ptr++};
                    uint16_t    offset{*reinterpret_cast<const uint16_t *>(ptr)};
                    ptr += sizeof(uint16_t);

                    outstream << "Ordinal 0x" << HexVal{ordinal} << "  Segment 0x" << HexVal{segment} << "  Offset 0x" << HexVal{offset} << "    ";
                    outstream << "MOVEABLE";
                    if (flags & 0x01)
                        outstream << " EXPORTED";
                    if (flags & 0x02)
                        outstream << " SHARED-DATA";
                    outstream << '\n';
                    ++ordinal;
                }
            }
            else    // 0x01 -- 0xFE:  FIXED segments
            {
                for (uint8_t i = 0; i < n_bundle; ++i)
                {
                    uint8_t     flags{*ptr++};
                    uint16_t    offset{*reinterpret_cast<const uint16_t *>(ptr)};
                    ptr += sizeof(uint16_t);

                    outstream << "Ordinal 0x" << HexVal{ordinal} << "  Segment 0x" << HexVal{indicator} << "  Offset 0x" << HexVal{offset} << "    FIXED ";

                    if (flags & 0x01)
                        outstream << " EXPORTED";
                    if (flags & 0x02)
                        outstream << " SHARED-DATA";
                    outstream << '\n';
                    ++ordinal;
                }
            }
        }
    }

    if (bundle_count == 0)
        outstream << "no entries\n";
}

void dump_entry_table(const NeExeInfo::EntryTable &table, std::ostream &outstream)
{
    outstream << "Entry Table\n-------------------------------------------\n";
    if (table.size())
    {
        size_t  n_bundle{1};
        for (const auto &bundle : table)
        {
            outstream << "Bundle " << n_bundle << ", " << bundle.entries().size() << " entries\n";
            for (const auto &entry : bundle.entries())
            {
                outstream << "Ordinal 0x" << HexVal{entry.ordinal()} << "  Segment 0x" << HexVal{entry.segment()} << "  Offset 0x" << HexVal{entry.offset()} << "    ";
                outstream << (bundle.movable() ? "MOVEABLE" : "FIXED");
                if (entry.is_exported())
                    outstream << " EXPORTED";
                if (entry.is_shared_data())
                    outstream << " SHARED-DATA";
                outstream << '\n';
            }

            ++n_bundle;
        }
    }
    else
    {
        outstream << "no entries\n";
    }
}

void print_segment_flags(uint16_t flags, std::ostream &outstream)
{
    outstream << ((flags & NeSegmentEntry::Preload) ? " PRELOAD " : " ");

    if (flags & NeSegmentEntry::RelocInfo)
        outstream << "RELOCINFO ";
    if (flags & NeSegmentEntry::Moveable)
        outstream << "MOVEABLE ";
    if (flags & NeSegmentEntry::Discard)
        outstream << "DISCARDABLE";
}

void dump_segment_table(const NeExeInfo::SegmentTable &table, uint16_t align, std::ostream &outstream)
{
    outstream << "Segment Table\n-------------------------------------------\n";
    if (table.size())
    {
        if (align == 0)
            align = 9;  // default shift-count value

        if (table[0].data_loaded)
        {
            for (const auto &entry : table)
            {
                auto sector_offset{static_cast<uint32_t>(entry.sector) << align};

                outstream << "Type: " << (entry.flags & NeSegmentEntry::DataSegment ? "DATA" : "CODE")
                          << "  Offset: 0x" << HexVal{sector_offset}
                          << "  Length: " << std::setw(5) << entry.length
                          << "  Min. Alloc: " << std::setw(5) << entry.min_alloc
                          << "  Flags: 0x" << HexVal{entry.flags};
                print_segment_flags(entry.flags, outstream);
                outstream << '\n';
                outstream << "Segment Data:\n" <<HexDump{entry.data.data(), entry.data.size()} << '\n';
            }
        }
        else
        {
            // display just a summary
            outstream << "Type  Sector offset  Length  Min. alloc  Flags\n"
                      << "----  -------------  ------  ----------  ------\n";

            for (const auto &entry : table)
            {
                auto sector_offset{static_cast<uint32_t>(entry.sector) << align};

                outstream << (entry.flags & NeSegmentEntry::DataSegment ? "DATA" : "CODE");
                outstream << "     0x" << HexVal{sector_offset};
                outstream << "   " << std::setw(5) << entry.length;
                outstream << "       " << std::setw(5) << entry.min_alloc;

                outstream << "  0x" << HexVal{entry.flags};
                print_segment_flags(entry.flags, outstream);
                outstream << '\n';
            }
        }
    }
    else
    {
        outstream << "no segment table entries\n";
    }
}

namespace {

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

void dump_resource_table(const NeExeInfo::ResourceTable &table, uint16_t shift_count, std::ostream &outstream)
{
    outstream << "Resources\n-------------------------------------------\n";
    if (table.size())
    {
        outstream << table.size() << " resource types:\n";

        for (const auto &entry : table)
        {
            std::string type_name{entry.type_name};
            if (entry.type & 0x8000)
                type_name = make_resource_type_name(entry.type);

            outstream << "    Resource Type: " << std::setw(15) << type_name << '\n';
            outstream << "    Count                    " << std::setw(5) << entry.count << '\n';

            for (const auto &resource : entry.resources)
            {
                std::string resource_name{resource.name};
                if (resource.id & 0x8000)
                    resource_name = '#' + std::to_string(resource.id & ~0x8000);

                outstream << "      " << resource_name << '\n';
                outstream << "        Location:       0x" << HexVal{resource.offset << shift_count} << '\n';
                outstream << "        Size:                " << std::setw(5) << (resource.length << shift_count) << '\n';
                outstream << "        Flags:              0x" << HexVal{resource.flags} << ' ';

                if (resource.flags & 0x10)
                    outstream << "MOVEABLE ";
                if (resource.flags & 0x20)
                    outstream << "PURE ";
                if (resource.flags & 0x40)
                    outstream << "PRELOAD";
                ///NOTE: There are other bits in the flags word, but I haven't found documentation for them.

                outstream << '\n';
                if (resource.data_loaded)
                    outstream << "Resource:\n\n" << HexDump{resource.bits.data(), resource.bits.size()} << '\n';
            }
            outstream << '\n';
        }
    }
    else
    {
        outstream << "no resources\n";
    }
}

void dump_resident_name_table(const NeExeInfo::NameContainer &table, std::ostream &outstream)
{
    outstream << "Resident Names\n-------------------------------------------\n";
    if (dump_ne_names(table, outstream) == 0)
        outstream << "No resident names\n";
}

void dump_non_resident_name_table(const NeExeInfo::NameContainer &table, std::ostream &outstream)
{
    outstream << "Non-Resident Names\n-------------------------------------------\n";
    if (dump_ne_names(table, outstream) == 0)
        outstream << "No non-resident names\n";
}

void dump_imported_name_table(const NeExeInfo::StringContainer &table, std::ostream &outstream)
{
    outstream << "Imported Names\n-------------------------------------------\n";
    if (dump_strings(table, outstream, true) == 0)
        outstream << "no imported names\n";
}

void dump_module_name_table(const NeExeInfo::StringContainer &table, std::ostream &outstream)
{
    outstream << "Module Names\n-------------------------------------------\n";
    if (dump_strings(table, outstream, false) == 0)
        outstream << "no module names\n";
}

}   // anonymous namespace

// Main function for dumping the NE portion of an executable
void dump_ne_info(const NeExeInfo &info, std::ostream &outstream)
{
    const char *separator{"\n\n"};

    outstream << separator << std::endl;
    dump_header(info, outstream);

    outstream << separator << std::endl;
    dump_resource_table(info.resource_table(), info.resource_shift_count(), outstream);

    outstream << separator << std::endl;
//    dump_entry_table(info.entry_table_bytes(), outstream);
    dump_entry_table(info.entry_table(), outstream);

    outstream << separator << std::endl;
    dump_segment_table(info.segment_table(), info.align_shift_count(), outstream);

    outstream << separator << std::endl;
    dump_resident_name_table(info.resident_names(), outstream);

    outstream << separator << std::endl;
    dump_non_resident_name_table(info.nonresident_names(), outstream);

    outstream << separator << std::endl;
    dump_imported_name_table(info.imported_names(), outstream);

    outstream << separator << std::endl;
    dump_module_name_table(info.module_names(), outstream);

    outstream << separator << std::endl;
}
