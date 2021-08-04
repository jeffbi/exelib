/// \file   nedump.cpp
/// Implementation of the function to dump a new NE-style executable.
/// 
/// \author Jeff Bienstadt
///

#include <format>
#include <ostream>

#include <NEExe.h>

namespace {

/////////////////////////////////////////////
// Helper Functions
////////////////////////////////////////////

// Helper for dumping a collection of NeName items
size_t dump_ne_names(const NeExeInfo::NameContainer &names, std::ostream &outstream)
{
    if (names.size())
        for (const auto &name : names)
            outstream << std::format("Ordinal: 0x{:04X}  Name: {}\n", name.ordinal, name.name);

    return names.size();
}

// Helper for dumping a collection of strings
size_t dump_strings(const NeExeInfo::StringContainer &strings, std::ostream &outstream)
{
    if (strings.size())
        for (const auto &str : strings)
            outstream << str << '\n';

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
            return std::format("0x{:02X}", type);
    }
}


////////////////////////////////////////////////////
// Functions for dumping individual NE areas
////////////////////////////////////////////////////

void dump_header(const NeExeInfo &info, std::ostream &outstream)
{
    outstream << "New NE header\n-------------------------------------------\n";

    const NeExeHeader &header = info.header();
    outstream << std::format("{}                            {}\n", header.flags & 0x8000 ? "Library:" : "Module: ", info.module_name());
    outstream << std::format("Description:                        {}\n", info.module_description());

    if (header.executable_type == static_cast<uint8_t>(NeExeType::Windows))
        outstream << std::format("Expected Windows version:           {}.{}\n\n",
                                 (header.expected_win_version >> 8) & 0xFF,
                                 header.expected_win_version & 0xFF);

    const char *format_string =
        "Signature:                          0x{:04X}\n"
        "Linker version:                        {:3}\n"
        "Linker revision:                       {:3}\n"
        "Entry Table offset:                 0x{:04X}\n"
        "Entry table size (bytes):            {:5}\n"
        "Checksum:                           0x{:04X}\n"
        "Flags:                              0x{:04X}\n"
        "Automatic data segment:             0x{:04X}\n"
        "Heap size:                          0x{:04X}\n"
        "Stack size:                         0x{:04X}\n"
        "Initial SS : SP:           0x{:04X} : 0x{:04X}\n"
        "Initial CS : IP:           0x{:04X} : 0x{:04X}\n"
        "Entries in Segment Table:            {:5}\n"
        "Entries in Module Table:             {:5}\n"
        "Non-resident Name Table size (bytes):{:5}\n"
        "Segment Table offset:               0x{:04X}\n"
        "Resource Table offset:              0x{:04X}\n"
        "Resident Name Table offset:         0x{:04X}\n"
        "Module Table offset:                0x{:04X}\n"
        "Import Table offset:                0x{:04X}\n"
        "Non-resident Name Table position:   0x{:08X}\n"
        "Number of movable entries:           {:5}\n"
        "Alignment shift count:               {:5}\n"
        "Number of Resource Table entries:    {:5}\n"
        "Executable Type:                    {}\n"
        "Additional Flags:                   0x{:04X}\n"
        "Gangload offset:                    0x{:04X}\n"
        "Gangload size:                      0x{:04X}\n"
        "Minimum code swap size:              {:5}\n";
    outstream << std::format(format_string,
                             header.signature,
                             header.linker_version,
                             header.linker_revision,
                             header.entry_table_offset,
                             header.entry_table_size,
                             header.checksum,
                             header.flags,
                             header.auto_data_segment,
                             header.inital_heap,
                             header.initial_stack,
                             header.initial_SS, header.initial_SP,
                             header.initial_CS, header.initial_IP,
                             header.num_segment_entries,
                             header.num_module_entries,
                             header.non_res_name_table_size,
                             header.segment_table_offset,
                             header.resource_table_offset,
                             header.res_name_table_offset,
                             header.module_table_offset,
                             header.import_table_offset,
                             header.non_res_name_table_pos,
                             header.num_movable_entries,
                             header.alignment_shift_count,
                             header.num_resource_entries,
                             get_exe_target(header.executable_type),
                             header.additional_flags,
                             header.gangload_offset,
                             header.gangload_size,
                             header.min_code_swap_size);
}

// This function requires some intimate knowlege of what the entry table
// looks like and how it works.
void dump_entry_table(const NeExeInfo::ByteContainer &table, std::ostream &outstream)
{
    size_t  bundle_count = 0;
    outstream << "Entry Table\n-------------------------------------------\n";
    if (table.size())
    {
        const auto *ptr = table.data();
        uint16_t    ordinal = 1;

        while (true)
        {
            uint8_t n_bundle = *ptr++;  // number of entries in this bundle
            if (n_bundle == 0)
                break;  // end of entry table;

            ++bundle_count;
            outstream << "Bundle " << bundle_count << ", " << static_cast<unsigned int>(n_bundle) << " entries\n";

            uint8_t indicator = *ptr++;

            if (indicator == 0x00)      // empty bundle
            {
                outstream << "(empty bundle)\n";
                ++ordinal;
            }
            else if (indicator == 0xFF) // MOVEABLE segments
            {
                for (uint8_t i = 0; i < n_bundle; ++i)
                {
                    uint8_t     flags = *ptr++;
                    ptr += sizeof(uint16_t);    // Skip over the INT 3F instruction bytes. we don't display them
                    uint8_t     segment = *ptr++;
                    uint16_t    offset = *reinterpret_cast<const uint16_t *>(ptr);
                    ptr += sizeof(uint16_t);

                    outstream << std::format("Ordinal 0x{:04X}  Segment 0x{:02X}  Offset 0x{:04X}    ", ordinal, segment, offset);
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
                    uint8_t     flags = *ptr++;
                    uint16_t    offset = *reinterpret_cast<const uint16_t *>(ptr);
                    ptr += sizeof(uint16_t);

                    outstream << std::format("Ordinal 0x{:04X}  Segment 0x{:02X}  Offset 0x{:04X}    ", ordinal, indicator, offset);
                    outstream << "FIXED";
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

void dump_segment_table(const NeExeInfo::SegmentContainer &table, uint16_t align, std::ostream &outstream)
{
    outstream << "Segment Table\n-------------------------------------------\n";
    if (table.size())
    {
        if (align == 0)
            align = 9;  // default shift-count value

        for (const auto &entry : table)
        {
            //auto flags = entry.flags;

            auto sector_offset = static_cast<uint16_t>(entry.sector) << align;

            outstream << std::format("{:4}  Sector offset: 0x{:08X}  Length: 0x{:04X}  Min. alloc size: 0x{:04X}  ",
                                     entry.flags & NeSegmentEntry::DataSegment ? "DATA" : "CODE",
                                     sector_offset,
                                     entry.length,
                                     entry.min_alloc);
            //std::string flags_string{entry.flags & NeSegmentEntry::Preload ? "PRELOAD" : ""};
            std::string flags_string{std::format("Flags: 0x{:04X}{}", entry.flags, entry.flags & NeSegmentEntry::Preload ? " PRELOAD" : "")};
            if (entry.flags & NeSegmentEntry::RelocInfo)
            {
                if (flags_string.size())
                    flags_string += ' ';
                flags_string += "RELOCINFO";
            }
            if (entry.flags & NeSegmentEntry::Moveable)
            {
                if (flags_string.size())
                    flags_string += ' ';
                flags_string += "MOVEABLE";
            }
            if (entry.flags & NeSegmentEntry::Discard)
            {
                if (flags_string.size())
                    flags_string += ' ';
                flags_string += "DISCARDABLE";
            }
            outstream << flags_string << '\n';
        }
    }
    else
    {
        outstream << "no segment table entries\n";
    }
}

//void dump_resource_table(const std::vector<NeResource> &resources, uint16_t shift_count, std::ostream &outstream)
void dump_resource_table(const NeExeInfo::ResourceContainer &resources, uint16_t shift_count, std::ostream &outstream)
{
    outstream << "Resources\n-------------------------------------------\n";
    if (resources.size())
    {
        outstream << std::format("{} resource types:\n", resources.size());

        for (const auto &resource : resources)
        {
            outstream << std::format("    Resource Type: {:>15}\n", resource.type_name);
            outstream << std::format("    Count:                   {:5}\n", resource.count);
            for (const auto &info : resource.info)
            {
                outstream << "      " << info.name << '\n';
                outstream << std::format("        Location:       0x{:08X}\n"
                                         "        Size:                {:5}\n"
                                         "        Flags:          0x{:08X} ",  //TODO: Expand flags!!!
                                         info.offset << shift_count,
                                         info.length << shift_count,
                                         info.flags);
                if (info.flags & 0x10)
                    outstream << "MOVEABLE ";
                if (info.flags & 0x20)
                    outstream << "PURE ";
                if (info.flags & 0x40)
                    outstream << "PRELOAD";
                ///NOTE: There are other bits in the flags word, but I haven't found documentation for them.

                outstream << '\n';
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
    if (dump_strings(table, outstream) == 0)
        outstream << "no imported names\n";
}

void dump_module_name_table(const NeExeInfo::StringContainer &table, std::ostream &outstream)
{
    outstream << "Module Names\n-------------------------------------------\n";
    if (dump_strings(table, outstream) == 0)
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
