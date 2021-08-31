/// \file   exedump.cpp
/// The primary source file for the exedump sample.
///
/// \author Jeff Bienstadt
///

#include <exception>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

// exelib headers
#include <ExeInfo.h>
#include <MZExe.h>
#include <NEExe.h>
#include <PEExe.h>

#include "HexVal.h"
#include "LoadOptions.h"


void dump_ne_info(const NeExeInfo &info, std::ostream &outstream);  // in nedump.cpp
void dump_pe_info(const PeExeInfo &info, std::ostream &outstream);  // in pedump.cpp


void dump_mz_header(const MzExeHeader &header, std::ostream &outstream)
{
    outstream << "Old MZ header\n-------------------------------------------\n";
    outstream << "Signature:                          0x" << HexVal{header.signature} << '\n';
    outstream << "Bytes on last page:                  " << std::setw(5) << header.bytes_on_last_page << '\n';
    outstream << "Total pages:                         " << std::setw(5) << header.num_pages << '\n';
    outstream << "Number of relocation items:          " << std::setw(5) << header.num_relocation_items << '\n';
    outstream << "Number of paragraphs in header:      " << std::setw(5) << header.header_size << '\n';
    outstream << "Extra paragraphs required:           " << std::setw(5) << header.min_allocation << '\n';
    outstream << "Extra paragraphs requested:          " << std::setw(5) << header.requested_allocation << '\n';
    outstream << "Initial SS:                         0x" << HexVal{header.initial_SS} << '\n';
    outstream << "Initial SP:                         0x" << HexVal{header.initial_SP} << '\n';
    outstream << "Checksum:                           0x" << HexVal{header.checksum} << '\n';
    outstream << "Initial CS:                         0x" << HexVal{header.initial_CS} << '\n';
    outstream << "Initial IP:                         0x" << HexVal{header.initial_IP} << '\n';
    outstream << "Relocation Table position:          0x" << HexVal{header.relocation_table_pos} << '\n';
    outstream << "Overlay:                             " << std::setw(5) << header.overlay << '\n';
    outstream << "OEM ID:                             0x" << HexVal{header.oem_ID} << '\n';
    outstream << "OEM info:                           0x" << HexVal{header.oem_info} << '\n';
    outstream << "New header offset:              0x" << HexVal{header.new_header_offset} << '\n';
}

void dump_relocation_table(const MzExeInfo::RelocationTable &table, std::ostream &outstream)
{
    outstream << "\nRelocation Table:\n-------------------------------------------\n";

    if (table.size())
    {
        outstream << "Offset    Segment\n"
                  << "------    -------\n";
        for (const auto &entry : table)
            outstream << "0x" << HexVal{entry.offset} << "    0x" << HexVal{entry.segment} << '\n';
    }
    else
    {
        outstream << "No Relocation Table entries\n";
    }
}

void dump_exe_info(const ExeInfo &exe_info, std::ostream &outstream = std::cout)
{
    dump_mz_header(exe_info.mz_part()->header(), outstream);
    if (exe_info.mz_part()->relocation_table_loaded())
        dump_relocation_table(exe_info.mz_part()->relocation_table(), outstream);

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
        std::cout << "Dump of " << path << '\n';
        //dump_exe_info(ExeInfo(fs, LoadOptions::LoadAllData));   // Here we're loading all the raw data so we can output it in hexdumps
        dump_exe_info(ExeInfo(fs, LoadOptions::LoadDebugData));
    }
    else
    {
        throw std::runtime_error(std::string("Could not open file ") + path);
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
            try
            {
                dump_exe(argv[i]);
                if (i < argc - 1)
                    std::cout << "\n\n";
            }
            catch (const std::exception &ex)
            {
                std::cerr << ex.what() << std::endl;
            }
        }
    }
    else
    {
        usage();
        return 1;
    }

    return 0;
}
