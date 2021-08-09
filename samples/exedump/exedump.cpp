/// \file   exedump.cpp
/// The primary source file for the exedump sample.
///
/// \author Jeff Bienstadt
///

#include <version>
#include <exception>
#include <fstream>
#if defined(__cpp_lib_format)
#include <format>
#else
#include <cstdio>
#endif
#include <iostream>
#include <string>
#include <vector>

// exelib headers
#include <ExeInfo.h>
#include <MZExe.h>
#include <NEExe.h>
#include <PEExe.h>


void dump_ne_info(const NeExeInfo &info, std::ostream &outstream);  // in nedump.cpp
void dump_pe_info(const PeExeInfo &info, std::ostream &outstream);  // in pedump.cpp


void dump_mz_header(const MzExeHeader &header, std::ostream &outstream)
{
#if defined(__cpp_lib_format)
    const char *format_string =
        "Old MZ header\n-------------------------------------------\n"
        "Signature:                          0x{:04X}\n"
        "Bytes on last page:                  {:5}\n"
        "Total pages:                         {:5}\n"
        "Number of relocation items:          {:5}\n"
        "Number of paragraphs in header:      {:5}\n"
        "Extra paragraphs required:           {:5}\n"
        "Extra paragraphs requested:          {:5}\n"
        "Initial SS : SP:           0x{:04X} : 0x{:04X}\n"
        "Checksum:                           0x{:04X}\n"
        "Initial CS : IP:           0x{:04X} : 0x{:04X}\n"
        "Relocation Table position:          0x{:04X}\n"
        "Overlay:                             {:5}\n"
        "OEM ID:                             0x{:04X}\n"
        "OEM info:                           0x{:04X}\n"
        "New header offset:              0x{:08X}\n";

    outstream << std::format(format_string,
                             header.signature,
                             header.bytes_on_last_page,
                             header.num_pages,
                             header.num_relocation_items,
                             header.header_size,
                             header.min_allocation,
                             header.requested_allocation,
                             header.initial_SS, header.initial_SP,
                             header.checksum,
                             header.initial_CS, header.initial_IP,
                             header.relocation_table_pos,
                             header.overlay,
                             header.oem_ID,
                             header.oem_info,
                             header.new_header_offset);
#else
    char buffer[1024];
    const char *format_string =
        "Old MZ header\n-------------------------------------------\n"
        "Signature:                          0x%04X\n"
        "Bytes on last page:                  %5hu\n"
        "Total pages:                         %5hu\n"
        "Number of relocation items:          %5hu\n"
        "Number of paragraphs in header:      %5hu\n"
        "Extra paragraphs required:           %5hu\n"
        "Extra paragraphs requested:          %5hu\n"
        "Initial SS : SP:           0x%04hX : 0x%04hX\n"
        "Checksum:                           0x%04hX\n"
        "Initial CS : IP:           0x%04hX : 0x%04hX\n"
        "Relocation Table position:          0x%04hX\n"
        "Overlay:                             %5hu\n"
        "OEM ID:                             0x%04hX\n"
        "OEM info:                           0x%04hX\n"
        "New header offset:              0x%08X\n";

#if defined(_MSC_VER)
    int size = sprintf_s(buffer, sizeof(buffer), format_string,
#else
    int size = std::sprintf(buffer, format_string,
#endif
                                    header.signature,
                                    header.bytes_on_last_page,
                                    header.num_pages,
                                    header.num_relocation_items,
                                    header.header_size,
                                    header.min_allocation,
                                    header.requested_allocation,
                                    header.initial_SS, header.initial_SP,
                                    header.checksum,
                                    header.initial_CS, header.initial_IP,
                                    header.relocation_table_pos,
                                    header.overlay,
                                    header.oem_ID,
                                    header.ome_info,
                                    header.new_header_offset);
    outstream << buffer;
#endif
}

void dump_exe_info(const ExeInfo &exe_info, std::ostream &outstream = std::cout)
{
    dump_mz_header(exe_info.mz_part()->header(), outstream);

    switch (exe_info.executable_type())
    {
        case ExeType::Unknown:
            outstream << "Unrecognized new header type.\n";
            break;

        case ExeType::MZ:
            break;          // we've already dumped the MZ header

        case ExeType::LE:
        case ExeType::LX:
        {
            auto    type {static_cast<uint16_t>(exe_info.executable_type())};
            outstream << '\n'
                      << static_cast<char>(type & 0xFF)
                      << static_cast<char>((type >> 8) & 0xFF)
                      << "-type executable is not supported at this time.\n";
            break;
        }

        case ExeType::NE:
            if (exe_info.ne_part())
                dump_ne_info(*exe_info.ne_part(), outstream);
            break;

        case ExeType::PE:
            if (exe_info.pe_part())
                dump_pe_info(*exe_info.pe_part(), outstream);
            break;

        default:
            throw std::runtime_error("Something has gone horribly wrong with the executable type");
    }
}

void dump_exe(const char *path)
{
    std::ifstream   fs(path, std::ios::in | std::ios::binary);

    if (fs.is_open())
    {
        try
        {
            dump_exe_info(ExeInfo(fs));
        }
        catch (const std::exception &ex)
        {
            std::cerr << ex.what() << std::endl;
        }
    }
}

void usage()
{
    std::cerr << "Usage: exedump <filename> [<filename>...]\n";
}

int main(int argc, char **argv)
{
    if (argc >= 2)
    {
        for (int i = 1; i < argc; ++i)
        {
            std::cout << "Dump of " << argv[i] << '\n';
            dump_exe(argv[i]);
            if (i < argc - 1)
                std::cout << "\n\n";
        }
    }
    else
    {
        usage();
        return 1;
    }

    return 0;
}
