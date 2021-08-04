/// \file   pedump.cpp
/// Implementation of the function to dump a PE-style portable executable
/// 
/// \author Jeff Bienstadt
///

#include <ctime>
#include <format>
#include <ostream>

#include <PEExe.h>

namespace {

// Helper to format a timestamp (from the PE header) into a string for output.
std::string format_timestamp(uint32_t timestamp)
{
    time_t  tt = timestamp;
    char    buf[60];
#if defined(_MSC_VER)   // the Microsoft compiler insists that you use their gmtime_s function, or it generates a compiler error. Bah!
    tm      tm;
    gmtime_s(&tm, &tt);
    std::strftime(buf, sizeof(buf), "%c", &tm);
#else
    std::strftime(buf, sizeof(buf), "%c", std::gmtime(&tt));
#endif

    return buf;
}

// Helper to make the target_machine member of the PE header into a string for output.
std::string get_target_machine_string(uint16_t target)
{
    //TODO: Maybe use an unordered_map here?
    switch (target)
    {
        case PeExeHeader::MachineType::UNKNOWN:
            return "Unknown";
        case PeExeHeader::MachineType::AM33:
            return "Matsushita AM33";
        case PeExeHeader::MachineType::AMD64:
            return "x64";
        case PeExeHeader::MachineType::ARM:
            return "ARM little endian";
        case PeExeHeader::MachineType::ARM64:
            return "ARM64 little endian";
        case PeExeHeader::MachineType::ARMNT:
            return "ARM Thumb-2 little endian";
        case PeExeHeader::MachineType::EBC:
            return "EFI byte code";
        case PeExeHeader::MachineType::I386:
            return "Intel 386 or later processors and compatible processors";
        case PeExeHeader::MachineType::IA64:
            return "Intel Itanium processor family";
        case PeExeHeader::MachineType::M32R:
            return "Mitsubishi M32R little endian";
        case PeExeHeader::MachineType::MIPS16:
            return "MIPS16";
        case PeExeHeader::MachineType::MIPSFPU:
            return "MIPS with FPU";
        case PeExeHeader::MachineType::MIPSFPU16:
            return "MIPS16 with FPU";
        case PeExeHeader::MachineType::POWERPC:
            return "Power PC little endian";
        case PeExeHeader::MachineType::POWERPCFP:
            return "Power PC with floating point support";
        case PeExeHeader::MachineType::R4000:
            return "MIPS little endian";
        case PeExeHeader::MachineType::RISCV32:
            return "RISC-V 32-bit address space";
        case PeExeHeader::MachineType::RISCV64:
            return "RISC-V 64-bit address space";
        case PeExeHeader::MachineType::RISCV128:
            return "RISC-V 128-bit address space";
        case PeExeHeader::MachineType::SH3:
            return "Hitachi SH3";
        case PeExeHeader::MachineType::SH3DSP:
            return "Hitachi SH3 DSP";
        case PeExeHeader::MachineType::SH4:
            return "Hitachi SH4";
        case PeExeHeader::MachineType::SH5:
            return "Hitachi SH5";
        case PeExeHeader::MachineType::THUMB:
            return "Thumb";
        case PeExeHeader::MachineType::WCEMIPSV2:
            return "MIPS little-endian WCE v2";
        default:
            return "<Un-Recognized>";
    }
}

#include <utility>

// Dump the PE header.
void dump_header(PeExeHeader header, std::ostream &outstream)
{
    constexpr std::pair<PeExeHeader::Characteristics, const char *> characteristics[] {
        {PeExeHeader::Characteristics::EXECUTABLE_IMAGE, "EXECUTABLE_IMAGE"},
        {PeExeHeader::Characteristics::RELOCS_STRIPPED, "RELOCS_STRIPPED"},
        {PeExeHeader::Characteristics::LINE_NUMS_STRIPPED, "LINE_NUMS_STRIPPED"},
        {PeExeHeader::Characteristics::LOCAL_SYMS_STRIPPED, "LOCAL_SYMS_STRIPPED"},
        {PeExeHeader::Characteristics::AGGRESSIVE_WS_TRIM, "AGGRESSIVE_WS_TRIM"},
        {PeExeHeader::Characteristics::LARGE_ADDRESS_AWARE, "LARGE_ADDRESS_AWARE"},
        {PeExeHeader::Characteristics::BYTES_REVERSED_LO, "BYTES_REVERSED_LO"},
        {PeExeHeader::Characteristics::MACHINE_32BIT, "MACHINE_32BIT"},
        {PeExeHeader::Characteristics::DEBUG_STRIPPED, "DEBUG_STRIPPED"},
        {PeExeHeader::Characteristics::REMOVABLE_RUN_FROM_SWAP, "REMOVABLE_RUN_FROM_SWAP"},
        {PeExeHeader::Characteristics::NET_RUN_FROM_SWAP, "NET_RUN_FROM_SWAP"},
        {PeExeHeader::Characteristics::SYSTEM, "SYSTEM"},
        {PeExeHeader::Characteristics::DLL, "DLL"},
        {PeExeHeader::Characteristics::UP_SYSTEM_ONLY, "UP_SYSTEM_ONLY"},
        {PeExeHeader::Characteristics::BYTES_REVERSED_HI, "BYTES_REVERSED_HI"},
    };

    const char *format_string = 
        "New PE header\n-------------------------------------------\n"
        "Signature:             0x{:08X}\n"
        "Target machine:        0x{:04X} {}\n"
        "Number of sections:    {:10}\n"
        "Timestamp              {}\n"
        "Symbol Table offset:   0x{:08X}\n"
        "Number of symbols:     {:10}\n"
        "Optional header size:  {:10}\n"
        "Characteristics:       0x{:04X} ";
    outstream << std::format(format_string,
                             header.signature,
                             header.target_machine, get_target_machine_string(header.target_machine),
                             header.num_sections,
                             format_timestamp(header.timestamp),
                             header.symbol_table_offset,
                             header.num_symbols,
                             header.optional_header_size,
                             header.characteristics);
    // list characteristics
    for (auto &&pair : characteristics)
        if (header.characteristics & pair.first)
            outstream << pair.second << ' ';

    outstream << '\n';
}


}   // anonymous namespace


// Main function for dumping the PE portion of an executable
void dump_pe_info(const PeExeInfo &info, std::ostream &outstream)
{
    const char *separator{"\n\n"};

    outstream << separator << std::endl;
    dump_header(info.header(), outstream);
}
