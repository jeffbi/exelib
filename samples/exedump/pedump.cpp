/// \file   pedump.cpp
/// Implementation of the function to dump a PE-style portable executable
///
/// \author Jeff Bienstadt
///

#include <ctime>
#include <iomanip>
#include <ostream>
#include <string>
#include <utility>

#include <PEExe.h>
#include "HexVal.h"

namespace {

// Helper to format a timestamp (from the PE header) into a string for output.
std::string format_timestamp(uint32_t timestamp)
{
    if (timestamp == 0 || timestamp == 0xFFFFFFFF)
        return "";

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
    using ut = std::underlying_type<PeMachineType>::type;

    switch (target)
    {
        case static_cast<ut>(PeMachineType::Unknown):
            return "Unknown";
        case static_cast<ut>(PeMachineType::AM33):
            return "Matsushita AM33";
        case static_cast<ut>(PeMachineType::AMD64):
            return "x64";
        case static_cast<ut>(PeMachineType::ARM):
            return "ARM little endian";
        case static_cast<ut>(PeMachineType::ARM64):
            return "ARM64 little endian";
        case static_cast<ut>(PeMachineType::ARMNT):
            return "ARM Thumb-2 little endian";
        case static_cast<ut>(PeMachineType::EBC):
            return "EFI byte code";
        case static_cast<ut>(PeMachineType::I386):
            return "Intel 386 or later processors and compatible processors";
        case static_cast<ut>(PeMachineType::IA64):
            return "Intel Itanium processor family";
        case static_cast<ut>(PeMachineType::M32R):
            return "Mitsubishi M32R little endian";
        case static_cast<ut>(PeMachineType::MIPS16):
            return "MIPS16";
        case static_cast<ut>(PeMachineType::MIPSFPU):
            return "MIPS with FPU";
        case static_cast<ut>(PeMachineType::MIPSFPU16):
            return "MIPS16 with FPU";
        case static_cast<ut>(PeMachineType::PowerPC):
            return "Power PC little endian";
        case static_cast<ut>(PeMachineType::PowerPCFP):
            return "Power PC with floating point support";
        case static_cast<ut>(PeMachineType::R4000):
            return "MIPS little endian";
        case static_cast<ut>(PeMachineType::RISCV32):
            return "RISC-V 32-bit address space";
        case static_cast<ut>(PeMachineType::RISCV64):
            return "RISC-V 64-bit address space";
        case static_cast<ut>(PeMachineType::RISCV128):
            return "RISC-V 128-bit address space";
        case static_cast<ut>(PeMachineType::SH3):
            return "Hitachi SH3";
        case static_cast<ut>(PeMachineType::SH3DSP):
            return "Hitachi SH3 DSP";
        case static_cast<ut>(PeMachineType::SH4):
            return "Hitachi SH4";
        case static_cast<ut>(PeMachineType::SH5):
            return "Hitachi SH5";
        case static_cast<ut>(PeMachineType::Thumb):
            return "Thumb";
        case static_cast<ut>(PeMachineType::WCEMIPSv2):
            return "MIPS little-endian WCE v2";
        default:
            return "<Not Recognized>";
    }
}

// Dump the PE header.
void dump_header(const PeImageFileHeader &header, std::ostream &outstream)
{
    static constexpr std::pair<PeImageFileHeader::Characteristics, const char *> characteristics[] {
        {PeImageFileHeader::Characteristics::ExecutableImage, "EXECUTABLE_IMAGE"},
        {PeImageFileHeader::Characteristics::RelocsStripped, "RELOCS_STRIPPED"},
        {PeImageFileHeader::Characteristics::LineNumsStripped, "LINE_NUMS_STRIPPED"},
        {PeImageFileHeader::Characteristics::LocalSymsStripped, "LOCAL_SYMS_STRIPPED"},
        {PeImageFileHeader::Characteristics::AggressiveWsTrim, "AGGRESSIVE_WS_TRIM"},
        {PeImageFileHeader::Characteristics::LargeAddressAware, "LARGE_ADDRESS_AWARE"},
        {PeImageFileHeader::Characteristics::BytesReversedLO, "BYTES_REVERSED_LO"},
        {PeImageFileHeader::Characteristics::Machine32Bit, "MACHINE_32BIT"},
        {PeImageFileHeader::Characteristics::DebugStripped, "DEBUG_STRIPPED"},
        {PeImageFileHeader::Characteristics::RemovableRunFromSwap, "REMOVABLE_RUN_FROM_SWAP"},
        {PeImageFileHeader::Characteristics::NetRunFromSwap, "NET_RUN_FROM_SWAP"},
        {PeImageFileHeader::Characteristics::System, "SYSTEM"},
        {PeImageFileHeader::Characteristics::DLL, "DLL"},
        {PeImageFileHeader::Characteristics::UPSystemOnly, "UP_SYSTEM_ONLY"},
        {PeImageFileHeader::Characteristics::BytesReversedHI, "BYTES_REVERSED_HI"},
    };

    outstream << "New PE header\n-------------------------------------------\n";
    outstream << "Signature:             0x" << HexVal(header.signature) << '\n';
    outstream << "Target machine:            0x" << HexVal(header.target_machine) << ' ' << get_target_machine_string(header.target_machine) << '\n';
    outstream << "Number of sections:    " << std::setw(10) << header.num_sections << '\n';
    outstream << "Timestamp              " << format_timestamp(header.timestamp) << '\n';
    outstream << "Symbol Table offset:   0x" << HexVal(header.symbol_table_offset) << '\n';
    outstream << "Number of symbols:'    " << std::setw(10) << header.num_symbols << '\n';
    outstream << "Optional Header size:  " << std::setw(10) << header.optional_header_size << '\n';
    outstream << "Characteristics:           0x" << HexVal(header.characteristics) << ' ';

    // list characteristics
    for (const auto &pair : characteristics)
        if (header.characteristics & pair.first)
            outstream << pair.second << ' ';

    outstream << '\n';
}

void dump_optional_header_base(const PeOptionalHeaderBase &header, std::ostream &outstream)
{
    outstream << "Magic number:                     0x" << HexVal{header.magic} << '\n';
    outstream << "Linker version major:         " << std::setw(10) << static_cast<uint32_t>(header.linker_version_major) << '\n';
    outstream << "Linker version minor:         " << std::setw(10) << static_cast<uint32_t>(header.linker_version_minor) << '\n';
    outstream << "Code size:                    " << std::setw(10) << header.code_size << '\n';
    outstream << "Initialized Data size:        " << std::setw(10) << header.initialized_data_size << '\n';
    outstream << "Uninitialized Data size:      " << std::setw(10) << header.uninitialized_data_size << '\n';
    outstream << "Address of Entry Point:       0x" << HexVal{header.address_of_entry_point} << '\n';
    outstream << "Base of Code:                 0x" << HexVal{header.base_of_code} << '\n';
}

// Helper to make the subsystem member of the PE optional header into a string for output.
std::string get_subsystem_name(uint16_t subsystem)
{
    using ut = std::underlying_type<PeSubsystem>::type;

    switch (subsystem)
    {
        case static_cast<ut>(PeSubsystem::Unknown):
            return "An unknown subsystem";
        case static_cast<ut>(PeSubsystem::Native):
            return "Device drivers and native Windows processes";
        case static_cast<ut>(PeSubsystem::Windows_GUI):
            return "Windows graphical user interface (GUI)";
        case static_cast<ut>(PeSubsystem::Windows_CUI):
            return "The Windows character user interface (CUI)";
        case static_cast<ut>(PeSubsystem::OS2_CUI):
            return "The OS/2 character user interface (CUI)";
        case static_cast<ut>(PeSubsystem::Posix_CUI):
            return "The Posix character user interface (CUI)";
        case static_cast<ut>(PeSubsystem::NativeWindows):
            return "Native Win9x driver";
        case static_cast<ut>(PeSubsystem::WindowsCE_GUI):
            return "Windows CE";
        case static_cast<ut>(PeSubsystem::EfiApplication):
            return "An EFI application";
        case static_cast<ut>(PeSubsystem::EfiBootServiceDriver):
            return "An EFI driver with boot services";
        case static_cast<ut>(PeSubsystem::EfiRuntimeDriver):
            return "An EFI driver with run-time services";
        case static_cast<ut>(PeSubsystem::EfiROM):
            return "An EFI ROM image";
        case static_cast<ut>(PeSubsystem::XBox):
            return "Xbox";
        case static_cast<ut>(PeSubsystem::WindowsBootApplication):
            return "Windows boot application";
        case static_cast<ut>(PeSubsystem::XBoxCodeCatalog):
            return "Xbox code catalog";
        default:
            return "Unrecognized subsystem";
    }
}

// Helper to make the DLL characteristics member of the PE optional header into a string for output.
std::string get_dll_characteristics_string(uint16_t characteristics)
{
    using ut = std::underlying_type<PeDllCharacteristics>::type;

    static constexpr std::pair<PeDllCharacteristics, const char *> characteristic_pairs[] {
        {PeDllCharacteristics::HighEntropyVA, "HIGH_ENTROPY_VA"},
        {PeDllCharacteristics::DynamicBase, "DYNAMIC_BASE"},
        {PeDllCharacteristics::ForceIntegrity, "FORCE_INTEGRITY"},
        {PeDllCharacteristics::NxCompatible, "NX_COMPATIBLE"},
        {PeDllCharacteristics::NoIsolation, "NO_ISOLATION"},
        {PeDllCharacteristics::NoSEH, "NO_SEH"},
        {PeDllCharacteristics::NoBind, "NO_BIND"},
        {PeDllCharacteristics::AppContainer, "APPCONTAINER"},
        {PeDllCharacteristics::WmdDriver, "WDM_DRIVER"},
        {PeDllCharacteristics::ControlFlowGuard, "GUARD_CF"},
        {PeDllCharacteristics::TerminalServerAware, "TERMINAL_SERVER_AWARE"}
    };

    std::string rv;

    for (const auto &pair : characteristic_pairs)
    {
        if (characteristics & static_cast<ut>(pair.first))
        {
            rv += pair.second;
            rv += ' ';
        }
    }

    return rv;
}

template <typename T>
void dump_optional_header_common(const T &header, std::ostream &outstream)
{
    outstream << "Image Base:           " << (sizeof(header.image_base) == 8 ? "" : "        ") << "0x" << HexVal{header.image_base} << '\n';
    outstream << "Section Alignment:            " << std::setw(10) << header.section_alignment << '\n';
    outstream << "File Alignment:               " << std::setw(10) << header.file_alignment << '\n';
    outstream << "OS Version Major:             " << std::setw(10) << header.os_version_major << '\n';
    outstream << "OS Version Minor:             " << std::setw(10) << header.os_version_minor << '\n';
    outstream << "Image Version Major:          " << std::setw(10) << header.image_version_major << '\n';
    outstream << "Image Version Minor:          " << std::setw(10) << header.image_version_minor << '\n';
    outstream << "Subsystem Version Major:      " << std::setw(10) << header.subsystem_version_major << '\n';
    outstream << "Subsystem Version Minor:      " << std::setw(10) << header.subsystem_version_minor << '\n';
    outstream << "Win32 Version Value:          " << std::setw(10) << header.win32_version_value << '\n';
    outstream << "Size of Image:                " << std::setw(10) << header.size_of_image << '\n';
    outstream << "Size of Headers:              " << std::setw(10) << header.size_of_headers << '\n';
    outstream << "Checksum:                     0x" << HexVal{header.checksum} << '\n';
    outstream << "Subsystem:                    " << std::setw(10) << header.subsystem << ' ' << get_subsystem_name(header.subsystem) << '\n';
    outstream << "DLL Characteristics:              0x" << HexVal{header.dll_characteristics};
    std::string characteristics = get_dll_characteristics_string(header.dll_characteristics);
    if (characteristics.size() > 65)
        outstream << '\n' << "   ";
    outstream << ' ' << characteristics << '\n';
    outstream << "Stack Reserve Size: " << std::setw(20) << header.size_of_stack_reserve << '\n';
    outstream << "Stack Commit Size:  " << std::setw(20) << header.size_of_stack_commit << '\n';
    outstream << "Heap Reserve Size:  " << std::setw(20) << header.size_of_heap_reserve << '\n';
    outstream << "Heap Commit Size:   " << std::setw(20) << header.size_of_heap_commit << '\n';
    outstream << "Loader Flags:                 0x" << HexVal{header.loader_flags} << '\n';
    outstream << "Number of RVAs And Sizes:     " << std::setw(10) << header.num_rva_and_sizes << '\n';
}

void dump_optional_header(const PeOptionalHeader32 &header, std::ostream &outstream)
{
    outstream << "New PE optional header 32-bit\n-------------------------------------------\n";
    dump_optional_header_base(header, outstream);
    outstream << "Base of Data:                 0x" << HexVal{header.base_of_data} << '\n';
    dump_optional_header_common(header, outstream);
}

void dump_optional_header(const PeOptionalHeader64 &header, std::ostream &outstream)
{
    outstream << "New PE optional header 64-bit\n-------------------------------------------\n";
    dump_optional_header_base(header, outstream);
    outstream << "**** No Base of Data field in 64-bit header ****\n";
    dump_optional_header_common(header, outstream);
}

void dump_data_directory(const PeExeInfo::DataDirectory &data_dir, std::ostream &outstream)
{
    static constexpr const char *data_table_names[]
        {
            "Export Table",
            "Import Table",
            "Resource Table",
            "Exception Table",
            "Certificate Table",
            "Base Relocation Table",
            "Debug",
            "Architecture",
            "Global Pointer",
            "Thread Local Storage Table",
            "Load Configuration Table",
            "Bound Import Table",
            "Import Address Table",
            "Delay Import Descriptor",
            "CLR Runtime Header",
            "Reserved"
        };
    for (size_t i = 0; i < data_dir.size(); ++i)
    {
        const PeDataDirectoryEntry &entry = data_dir[i];

        outstream << "  0x" << HexVal{entry.virtual_address} << "  " << std::setw(10) << entry.size << "  ";
        if (i < (sizeof(data_table_names) / sizeof(data_table_names[0])))
            outstream << data_table_names[i] << '\n';
        else
            outstream << "???" << '\n';
    }
}

void dump_section_headers(const PeExeInfo::SectionHeaderContainer &headers, std::ostream &outstream)
{
    outstream << "Section Headers\n-------------------------------------------\n";

    char name_buffer[sizeof(PeSectionHeader::name) / sizeof(PeSectionHeader::name[0]) + 1] {0};

    for (size_t i = 0; i < headers.size(); ++i)
    {
        outstream << "\nSection Header #" << i + 1 << '\n';

        const PeSectionHeader &header = headers[i];

        // !!! This is incomplete and a bit of a cheat.
        // !!! The contents of the name array is a UTF-8 encoded name.
        // !!! Because this sample does not have a UTF-8 decoder, we
        // !!! assume that the content is ASCII. This could result in
        // !!! odd characters being written to the stream.

        // If the name occupies exactly eight bytes, it is not nul-terminated,
        // so we copy the name into a nul-terminated temporary buffer.
        std::memcpy(name_buffer, header.name, sizeof(header.name));
        outstream << "    Name:                     " << std::setw(8) << name_buffer << '\n';

        outstream << "    Virtual size:           " << std::setw(10) << header.virtual_size << '\n';
        outstream << "    Virtual address:        0x" << HexVal{header.virtual_address} << '\n';
        outstream << "    Raw data size:          " << std::setw(10) << header.size_of_raw_data << '\n';
        outstream << "    Raw data offset:        0x" << HexVal{header.raw_data_position} << '\n';
        outstream << "    Relocations offset:     0x" << HexVal{header.relocations_position} << '\n';
        outstream << "    Line numbers offset:    0x" << HexVal{header.line_numbers_position} << '\n';
        outstream << "    Number of relocations:       " << std::setw(5) << header.number_of_relocations << '\n';
        outstream << "    Number of line numbers:      " << std::setw(5) << header.number_of_line_numbers << '\n';
        outstream << "    Characteristics:        0x" << HexVal{header.characteristics} << '\n';   //TODO: dump characteristics!!!
    }
}

}   // anonymous namespace


// Main function for dumping the PE portion of an executable
void dump_pe_info(const PeExeInfo &info, std::ostream &outstream)
{
    const char *separator{"\n\n"};

    outstream << separator << std::endl;
    dump_header(info.header(), outstream);
    outstream << separator << std::endl;

    if (info.optional_header_32())
    {
        dump_optional_header(*info.optional_header_32(), outstream);
    }
    else if (info.optional_header_64())
    {
        dump_optional_header(*info.optional_header_64(), outstream);
    }
    else
    {
        outstream << "No PE optional header found!\n";
        return;
    }
    // Data Directory is part of the header (32- and 64-bit)
    dump_data_directory(info.data_directory(), outstream);
    outstream << separator << std::endl;

    dump_section_headers(info.section_headers(), outstream);
}
