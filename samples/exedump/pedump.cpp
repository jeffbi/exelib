/// \file   pedump.cpp
/// Implementation of the function to dump a PE-style portable executable
///
/// \author Jeff Bienstadt
///

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <iterator>
#include <ostream>
#include <sstream>
#include <string>
#include <utility>

#include <PEExe.h>
#include "HexVal.h"

namespace {

std::string guid_to_string(const Guid &guid)
{
    std::ostringstream  ss;
    const auto p = &guid.data4[0];

    ss << '{' << HexVal{guid.data1}
       << '-' << HexVal{guid.data2}
       << '-' << HexVal{guid.data3}
       << '-' << HexVal{*(p + 0)} << HexVal{*(p + 1)}
       << '-' << HexVal{*(p + 2)} << HexVal{*(p + 3)} << HexVal{*(p + 4)} << HexVal{*(p + 5)} << HexVal{*(p + 6)} << HexVal{*(p + 7)}
       << '}';

    return ss.str();
}

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
    using ut = std::underlying_type<PeImageFileHeader::MachineType>::type;

    switch (target)
    {
        case static_cast<ut>(PeImageFileHeader::MachineType::Unknown):
            return "Unknown";
        case static_cast<ut>(PeImageFileHeader::MachineType::AM33):
            return "Matsushita AM33";
        case static_cast<ut>(PeImageFileHeader::MachineType::AMD64):
            return "x64";
        case static_cast<ut>(PeImageFileHeader::MachineType::ARM):
            return "ARM little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::ARM64):
            return "ARM64 little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::ARMNT):
            return "ARM Thumb-2 little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::EBC):
            return "EFI byte code";
        case static_cast<ut>(PeImageFileHeader::MachineType::I386):
            return "Intel 386 or later processors and compatible processors";
        case static_cast<ut>(PeImageFileHeader::MachineType::IA64):
            return "Intel Itanium processor family";
        case static_cast<ut>(PeImageFileHeader::MachineType::M32R):
            return "Mitsubishi M32R little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::MIPS16):
            return "MIPS16";
        case static_cast<ut>(PeImageFileHeader::MachineType::MIPSFPU):
            return "MIPS with FPU";
        case static_cast<ut>(PeImageFileHeader::MachineType::MIPSFPU16):
            return "MIPS16 with FPU";
        case static_cast<ut>(PeImageFileHeader::MachineType::PowerPC):
            return "Power PC little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::PowerPCFP):
            return "Power PC with floating point support";
        case static_cast<ut>(PeImageFileHeader::MachineType::R4000):
            return "MIPS little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::RISCV32):
            return "RISC-V 32-bit address space";
        case static_cast<ut>(PeImageFileHeader::MachineType::RISCV64):
            return "RISC-V 64-bit address space";
        case static_cast<ut>(PeImageFileHeader::MachineType::RISCV128):
            return "RISC-V 128-bit address space";
        case static_cast<ut>(PeImageFileHeader::MachineType::SH3):
            return "Hitachi SH3";
        case static_cast<ut>(PeImageFileHeader::MachineType::SH3DSP):
            return "Hitachi SH3 DSP";
        case static_cast<ut>(PeImageFileHeader::MachineType::SH4):
            return "Hitachi SH4";
        case static_cast<ut>(PeImageFileHeader::MachineType::SH5):
            return "Hitachi SH5";
        case static_cast<ut>(PeImageFileHeader::MachineType::Thumb):
            return "Thumb";
        case static_cast<ut>(PeImageFileHeader::MachineType::WCEMIPSv2):
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
    outstream << "Timestamp              0x" << HexVal{header.timestamp} << ' ' << format_timestamp(header.timestamp) << '\n';
    outstream << "Symbol Table offset:   0x" << HexVal{header.symbol_table_offset} << '\n';
    outstream << "Number of symbols:'    " << std::setw(10) << header.num_symbols << '\n';
    outstream << "Optional Header size:  " << std::setw(10) << header.optional_header_size << '\n';
    outstream << "Characteristics:           0x" << HexVal(header.characteristics) << ' ';

    // list characteristics
    for (const auto &pair : characteristics)
        if (header.characteristics & static_cast<std::underlying_type<PeImageFileHeader::Characteristics>::type>(pair.first))
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

void dump_exports_table(const PeExports &exports, std::ostream &outstream)
{
    outstream << "Exports\n-------------------------------------------\n";
    outstream << "DLL name:     " << exports.name << '\n'
              << "Export flags:          0x" << HexVal{exports.directory.export_flags} << '\n'
              << "Timestamp:             0x" << HexVal{exports.directory.timestamp} << ' ' << format_timestamp(exports.directory.timestamp) << '\n'
              << "Version major:              " << std::setw(5) << exports.directory.version_major << '\n'
              << "Version minor:              " << std::setw(5) << exports.directory.version_minor << '\n'
              << "Name RVA:              0x" << HexVal{exports.directory.name_rva} << '\n'
              << "Ordinal base:          " << std::setw(10) << exports.directory.ordinal_base << '\n'
              << "Address Table entries: " << std::setw(10) << exports.directory.num_address_table_entries << '\n'
              << "Name pointers:         " << std::setw(10) << exports.directory.num_name_pointers << '\n'
              << "Export Address RVA:    0x" << HexVal{exports.directory.export_address_rva} << '\n'
              << "Name Pointer RVA:      0x" << HexVal{exports.directory.name_pointer_rva} << '\n'
              << "Ordinal Table RVA:     0x" << HexVal{exports.directory.ordinal_table_rva} << '\n';

    outstream << "\n    Ordinal  RVA         Name"
              << "\n    -------  ---         ----\n";
    for (uint16_t i = 0; i < exports.address_table.size(); ++i)
    {
        if (exports.address_table[i].export_rva)
        {
            outstream << "      " << std::setw(5) << i + exports.directory.ordinal_base
                      << "  0x" << HexVal{exports.address_table[i].export_rva};

            const auto it = std::find(exports.ordinal_table.begin(), exports.ordinal_table.end(), i);
            if (it != exports.ordinal_table.end())
            {
                outstream << "  " << exports.name_table[std::distance(exports.ordinal_table.begin(), it)];
#if !defined(EXELIB_NO_LOAD_FORWARDERS)
                if (exports.address_table[i].is_forwarder)
                    outstream << " => " << exports.address_table[i].forwarder_name;
#endif
            }
            outstream << '\n';
        }
    }
}

void dump_imports_table(const PeExeInfo::ImportDirectory &imports, std::ostream &outstream)
{
    outstream << "Imports\n-------------------------------------------\n";
    outstream << "Number of imported modules: " << imports.size() << '\n';
    for (const auto &entry : imports)
    {
        outstream << "    " << entry.module_name << '\n'
                  << "        Import Address Table:               0x" << HexVal{entry.import_address_table_rva} << '\n'
                  << "        Import Lookup Table:                0x" << HexVal{entry.import_lookup_table_rva} << '\n'
                  << "        Time Stamp:                         0x" << HexVal{entry.timestamp} << ' ' << format_timestamp(entry.timestamp) << '\n'
                  << "        Index of first forwarder reference: " << std::setw(10) << entry.forwarder_chain << '\n'
                  << "        Number of imported functions:       " << std::setw(10) << entry.lookup_table.size() << '\n'
                  << "            Hint or Ordinal  Name\n"
                  << "            ---------------  ----\n";

        for (const auto &lookup_entry : entry.lookup_table)
        {
            outstream << "                ";

            if (lookup_entry.ord_name_flag)
                outstream << "0x" << HexVal(lookup_entry.ordinal);
            else
                outstream << "0x" << HexVal{lookup_entry.hint} << "       " << lookup_entry.name;

            outstream << '\n';
        }
        outstream << '\n';
    }
}

std::vector<std::string> get_section_header_characteristic_strings(uint32_t characteristics)
{
    using ut = std::underlying_type<PeSectionHeaderCharacteristics>::type;

    static constexpr std::pair<PeSectionHeaderCharacteristics, const char *> characteristic_pairs[] {
        {PeSectionHeaderCharacteristics::NoPadding, "No Padding (obsolete)"},
        {PeSectionHeaderCharacteristics::ExecutableCode, "Executable code"},
        {PeSectionHeaderCharacteristics::InitializedData, "Initialized data"},
        {PeSectionHeaderCharacteristics::UninitializedData, "Uninitialized data"},
        {PeSectionHeaderCharacteristics::LinkOther, "(reserved)"},
        {PeSectionHeaderCharacteristics::LinkInfo, "Comments"},
        {PeSectionHeaderCharacteristics::LinkRemove, "To be removed"},
        {PeSectionHeaderCharacteristics::LinkCOMDAT, "COMDAT"},
        {PeSectionHeaderCharacteristics::GlobalPointerData, "Global Pointer data"},
        {PeSectionHeaderCharacteristics::MemPurgable, "MEM_PURGABLE or MEM_16BIT (reserved)"},
        {PeSectionHeaderCharacteristics::MemLocked, "(reserved)"},
        {PeSectionHeaderCharacteristics::MemPreload, "(reserved)"},
        {PeSectionHeaderCharacteristics::Align1Bytes, "Align data 1-byte boundary"},
        {PeSectionHeaderCharacteristics::Align2Bytes, "Align data 2-byte boundary"},
        {PeSectionHeaderCharacteristics::Align4Bytes, "Align data 4-byte boundary"},
        {PeSectionHeaderCharacteristics::Align8Bytes, "Align data 8-byte boundary"},
        {PeSectionHeaderCharacteristics::Align16Bytes, "Align data 16-byte boundary"},
        {PeSectionHeaderCharacteristics::Align32Bytes, "Align data 32-byte boundary"},
        {PeSectionHeaderCharacteristics::Align64Bytes, "Align data 64-byte boundary"},
        {PeSectionHeaderCharacteristics::Align128Bytes, "Align data 128-byte boundary"},
        {PeSectionHeaderCharacteristics::Align256Bytes, "Align data 256-byte boundary"},
        {PeSectionHeaderCharacteristics::Align512Bytes, "Align data 512-byte boundary"},
        {PeSectionHeaderCharacteristics::Align1024Bytes, "Align data 1024-byte boundary"},
        {PeSectionHeaderCharacteristics::Align2048Bytes, "Align data 2048-byte boundary"},
        {PeSectionHeaderCharacteristics::Align4096Bytes, "Align data 4096-byte boundary"},
        {PeSectionHeaderCharacteristics::Align8192Bytes, "Align data 8192-byte boundary"},
        {PeSectionHeaderCharacteristics::LinkNRelocOverflow, "Extended relocations"},
        {PeSectionHeaderCharacteristics::MemDiscardable, "Discardable"},
        {PeSectionHeaderCharacteristics::MemNotCached, "Not Cacheable"},
        {PeSectionHeaderCharacteristics::MemNotPaged, "Not Pageable"},
        {PeSectionHeaderCharacteristics::MemShared, "Shareable"},
        {PeSectionHeaderCharacteristics::MemExecute, "Executable"},
        {PeSectionHeaderCharacteristics::MemRead, "Readable"},
        {PeSectionHeaderCharacteristics::MemWrite, "Writeable"}
    };

    std::vector<std::string>    rv;

    for (const auto &pair : characteristic_pairs)
        if (characteristics & static_cast<ut>(pair.first))
            rv.push_back(pair.second);

    return rv;
}

const char *get_debug_type_name(uint32_t type)
{
    using ut = std::underlying_type<PeDebugType>::type;

    switch (type)
    {
        case static_cast<ut>(PeDebugType::Unknown):
            return "Unknown";
        case static_cast<ut>(PeDebugType::COFF):
            return "COFF";
        case static_cast<ut>(PeDebugType::CodeView):
            return "CodeView";
        case static_cast<ut>(PeDebugType::FPO):
            return "FPO";
        case static_cast<ut>(PeDebugType::Misc):
            return "Misc";
        case static_cast<ut>(PeDebugType::Exception):
            return "Exception";
        case static_cast<ut>(PeDebugType::Fixup):
            return "Fixup";
        case static_cast<ut>(PeDebugType::OMapToSource):
            return "OMapToSource";
        case static_cast<ut>(PeDebugType::OMapFromSource):
            return "OMapFromSource";
        case static_cast<ut>(PeDebugType::Borland):
            return "Borland";
        case static_cast<ut>(PeDebugType::Reserved):
            return "Reserved";
        case static_cast<ut>(PeDebugType::CLSID):
            return "CLSID";
        case static_cast<ut>(PeDebugType::VC_Feature):
            return "VC_FEATURE";
        case static_cast<ut>(PeDebugType::POGO):
            return "POGO";
        case static_cast<ut>(PeDebugType::ILTCG):
            return "ILTCG";
        case static_cast<ut>(PeDebugType::MPX):
            return "MPX";
        case static_cast<ut>(PeDebugType::Repro):
            return "Repro";
        case static_cast<ut>(PeDebugType::ExDllCharacteristics):
            return "ExDllCharacteristics";
        default:
            return "Unrecognized debug type";
    }
}
void dump_debug_directory(const PeExeInfo::DebugDirectory &debug_directory, std::ostream &outstream)
{
    outstream << "Debug Directory\n-------------------------------------------\n";

    for (const auto &entry : debug_directory)
    {
        outstream << "Characteristics:     0x" << HexVal{entry.characteristics} << '\n'
                  << "Time Stamp:          0x" << HexVal{entry.timestamp} << ' ' << format_timestamp(entry.timestamp) << '\n'
                  << "Version Major:            " << std::setw(5) << entry.version_major << '\n'
                  << "Version Minor:            " << std::setw(5) << entry.version_minor << '\n'
                  << "Type:                " << std::setw(10) << entry.type << ' ' << get_debug_type_name(entry.type) << '\n'
                  << "Size of Data:        " << std::setw(10) << entry.size_of_data << '\n'
                  << "Address of Raw Data: 0x" << HexVal{entry.address_of_raw_data} << '\n'
                  << "Pointer to Raw Data: 0x" << HexVal{entry.pointer_to_raw_data} << '\n';
        if (entry.type == static_cast<std::underlying_type<PeDebugType>::type>(PeDebugType::CodeView))
        {
            auto pcv = entry.make_cv_struct();

            if (pcv)
            {
                if (pcv->cv_signature == entry.SignaturePDB20)
                {
                    auto ptr = static_cast<PeDebugCvPDB20 *>(pcv.get());
                    outstream << "    Format: NB10, offset=" << ptr->offset << ", signature = " << ptr->signature << ", Age = " << ptr->age << ", " << ptr->pdb_filepath << '\n';
                }
                else if (pcv->cv_signature == entry.SignaturePDB70)
                {
                    auto ptr = static_cast<PeDebugCvPDB70 *>(pcv.get());
                    outstream << "    Format: RSDS, signature=" << guid_to_string(ptr->signature) << ", Age=" << ptr->age << ", " << ptr->pdb_filepath << '\n';
                }
            }
        }
#if !defined(EXELIB_NO_DEBUG_MISC_TYPE)
        else if (entry.type == static_cast<std::underlying_type<PeDebugType>::type>(PeDebugType::Misc))
        {
            auto ptr = entry.make_misc_struct();
            if (ptr)
            {
                if (ptr->data_type == PeDebugMisc::DataTypeExeName)
                {
                    outstream << "    Data Type=" << ptr->data_type << ", Length=" << ptr->length << ", Unicode=" << (ptr->unicode ? "yes" : "no") << ", ";
                    if (ptr->unicode)
                    {
                        outstream << "<UTF-16 Unicode name>\n";
                    }
                    else
                    {
                        outstream << reinterpret_cast<const char *>(ptr->data.data());
                    }
                }
            }
        }
#endif
        else if (entry.type == static_cast<std::underlying_type<PeDebugType>::type>(PeDebugType::VC_Feature))
        {
            // Counts: Pre-VC++ 11.00=0, C/C++=28, /GS=28, /sdl=1, guardN=27
            if (entry.data.size() >= sizeof(uint32_t) * 5)
            {
                auto ptr = entry.make_vc_feature_struct();

                if (ptr)
                {
                    outstream << "    Counts: Pre-VC++ 11=" << ptr->pre_vc11
                              << ", C/C++=" << ptr->cpp
                              << ", /GS=" << ptr->gs
                              << ", /sdl=" << ptr->sdl
                              << ", guardN=" << ptr->guard_n << '\n';
                }
            }
        }
        else if (entry.data_loaded)
        {
            outstream << "Raw debug data:\n" << HexDump{entry.data.data(), entry.data.size()} << '\n';
        }
        outstream << "----------\n";
    }
}

template <typename T>
void dump_sections(const PeExeInfo::SectionTable &sections, T image_base, std::ostream &outstream)
{
    outstream << "Sections\n-------------------------------------------\n";

    char name_buffer[sizeof(PeSectionHeader::name) / sizeof(PeSectionHeader::name[0]) + 1] {0};

    size_t n = 1;
    for (const auto &section : sections)
    {
        outstream << "\nSection Header #" << n << '\n';

        const auto &header = section.header();

        // !!! This is incomplete and a bit of a cheat.
        // !!! Microsoft's documetation says that the contents of the
        // !!! name array is a UTF-8 encoded name. Because this sample
        // !!! does not have a UTF-8 decoder, we assume that the content
        // !!! is ANSI. This could result in odd characters being written
        // !!! to the stream.

        // If the name occupies exactly eight bytes, it is not nul-terminated,
        // so we copy the name into a nul-terminated temporary buffer.
        std::memcpy(name_buffer, header.name, sizeof(header.name));
        outstream << "    Name:                     " << std::setw(8) << name_buffer << '\n';

        auto va = header.virtual_address + image_base;

        outstream << "    Virtual size:           " << std::setw(10) << header.virtual_size << '\n';
        outstream << "    Virtual address:        0x" << HexVal{header.virtual_address} << " (0x" << HexVal{va};
        if (header.virtual_size)
            outstream << " -- 0x" << HexVal{va + header.virtual_size - 1};
        outstream << ")\n";
        outstream << "    Raw data size:          " << std::setw(10) << header.size_of_raw_data << '\n';
        outstream << "    Raw data offset:        0x" << HexVal{header.raw_data_position} << '\n';
        outstream << "    Relocations offset:     0x" << HexVal{header.relocations_position} << '\n';
        outstream << "    Line numbers offset:    0x" << HexVal{header.line_numbers_position} << '\n';
        outstream << "    Number of relocations:       " << std::setw(5) << header.number_of_relocations << '\n';
        outstream << "    Number of line numbers:      " << std::setw(5) << header.number_of_line_numbers << '\n';
        outstream << "    Characteristics:        0x" << HexVal{header.characteristics} << '\n';

        auto characteristics = get_section_header_characteristic_strings(header.characteristics);

        for (const auto &c : characteristics)
            outstream << "        " << c << '\n';

        if (section.data_loaded())
        {
            outstream << "\nSection Data #" << n << '\n';
            outstream << BasicHexDump{section.data().data(), section.data().size(), va};
        }

        ++n;
    }
}

const char *get_table_type_name(PeCliMetadataTableId id)
{
    switch (id)
    {
        case PeCliMetadataTableId::Assembly:
            return "Assembly";
        case PeCliMetadataTableId::AssemblyOS:
            return "AssemblyOS";
        case PeCliMetadataTableId::AssemblyProcessor:
            return "AssemblyProcessor";
        case PeCliMetadataTableId::AssemblyRef:
            return "AssemblyRef";
        case PeCliMetadataTableId::AssemblyRefOS:
            return "AssemblyRefOS";
        case PeCliMetadataTableId::AssemblyRefProcessor:
            return "AssemblyRefProcessor";
        case PeCliMetadataTableId::ClassLayout:
            return "ClassLayout";
        case PeCliMetadataTableId::Constant:
            return "Constant";
        case PeCliMetadataTableId::CustomAttribute:
            return "CustomAttribute";
        case PeCliMetadataTableId::DeclSecurity:
            return "DeclSecurity";
        case PeCliMetadataTableId::EventMap:
            return "EventMap";
        case PeCliMetadataTableId::Event:
            return "Event";
        case PeCliMetadataTableId::ExportedType:
            return "ExportedType";
        case PeCliMetadataTableId::Field:
            return "Field";
        case PeCliMetadataTableId::FieldLayout:
            return "FieldLayout";
        case PeCliMetadataTableId::FieldMarshal:
            return "FieldMarshal";
        case PeCliMetadataTableId::FieldRVA:
            return "FieldRVA";
        case PeCliMetadataTableId::File:
            return "File";
        case PeCliMetadataTableId::GenericParam:
            return "GenericParam";
        case PeCliMetadataTableId::GenericParamConstraint:
            return "GenericParamConstraint";
        case PeCliMetadataTableId::ImplMap:
            return "ImplMap";
        case PeCliMetadataTableId::InterfaceImpl:
            return "InterfaceImpl";
        case PeCliMetadataTableId::ManifestResource:
            return "ManifestResource";
        case PeCliMetadataTableId::MemberRef:
            return "MemberRef";
        case PeCliMetadataTableId::MethodDef:
            return "MethodDef";
        case PeCliMetadataTableId::MethodImpl:
            return "MethodImpl";
        case PeCliMetadataTableId::MethodSemantics:
            return "MethodSemantics";
        case PeCliMetadataTableId::MethodSpec:
            return "MethodSpec";
        case PeCliMetadataTableId::Module:
            return "Module";
        case PeCliMetadataTableId::ModuleRef:
            return "ModuleRef";
        case PeCliMetadataTableId::NestedClass:
            return "NestedClass";
        case PeCliMetadataTableId::Param:
            return "Param";
        case PeCliMetadataTableId::Property:
            return "Property";
        case PeCliMetadataTableId::PropertyMap:
            return "PropertyMap";
        case PeCliMetadataTableId::StandAloneSig:
            return "StandAloneSig";
        case PeCliMetadataTableId::TypeDef:
            return "TypeDef";
        case PeCliMetadataTableId::TypeRef:
            return "TypeRef";
        case PeCliMetadataTableId::TypeSpec:
            return "TypeSpec";
    }

    // we should never get here
    return "<unknown>";
}


// This is just a little helper, used when dumping metadata tables.
// Zero is not a valid index into the #Strings stream, but is often
// used as null, meaning no string.
inline std::string get_metadata_string(const PeCliMetadata &metadata, uint32_t index)
{
    if (index == 0)         // 0 is not a valid index into the #Strings stream,
        return {"<null>"};  // but is often used as null, meaning no string.

    return metadata.get_string(index);
}

void dump_assembly_table(const std::vector<PeCliMetadataRowAssembly> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "Assembly table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  Assembly [" << count++ << "]\n";
        outstream << "    Hash Algorithm ID:    0x" << HexVal{entry.hash_alg_id} << '[';
        switch (entry.hash_alg_id)
        {
            case 0x0000:
                outstream << "None";
                break;
            case 0x8003:
                outstream << "MD5";
                break;
            case 0x8004:
                outstream << "SHA1";
                break;
            default:
                outstream << "unrecognized ID";
                break;
        }
        outstream << "]\n";
        outstream << "    Major version:        " << entry.major_version << '\n';
        outstream << "    Minor version:        " << entry.minor_version << '\n';
        outstream << "    Build number:         " << entry.build_number << '\n';
        outstream << "    Revision number:      " << entry.revision_number << '\n';
        outstream << "    Flags:                0x" << HexVal{entry.flags} << '\n';     //TODO: Expand these!!!
        outstream << "    Public key:           " << entry.public_key << '\n';          // Index into #Blob heap
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
        outstream << "    Culture:              " << get_metadata_string(metadata, entry.culture) << '\n';
    }
    outstream << std::endl;
}

void dump_assembly_os_table(const std::vector<PeCliMetadataRowAssemblyOS> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "AssemblyOS table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  AssemblyOS [" << count++ << "]\n";
        outstream << "    OS platform ID:       " << entry.os_platformID << '\n';
        outstream << "    OS major version:     " << entry.os_major_version << '\n';
        outstream << "    OS minor version:     " << entry.os_minor_version << '\n';
    }
    outstream << std::endl;
}

void dump_assembly_processor_table(const std::vector<PeCliMetadataRowAssemblyProcessor> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "AssemblyProcessor table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  AssemblyProcessor [" << count++ << "]\n";
        outstream << "    Processor:       " << entry.processor << '\n';
    }
    outstream << std::endl;
}

void dump_assembly_ref_table(const std::vector<PeCliMetadataRowAssemblyRef> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "AssemblyRef table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  AssemblyRef [" << count++ << "]\n";
        outstream << "    Major version:        " << entry.major_version << '\n';
        outstream << "    Minor version:        " << entry.minor_version << '\n';
        outstream << "    Build number:         " << entry.build_number << '\n';
        outstream << "    Revision number:      " << entry.revision_number << '\n';
        outstream << "    Flags:                0x" << HexVal{entry.flags} << '\n';     //TODO: Expand these!!!
        outstream << "    Public key or token:  " << entry.public_key_or_token << '\n';          // Index into #Blob heap
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
        outstream << "    Culture:              " << get_metadata_string(metadata, entry.culture) << '\n';
        outstream << "    Hash value            " << entry.hash_value << '\n';  // Index into the #Blob heap
    }
    outstream << std::endl;
}

void dump_assembly_ref_os_table(const std::vector<PeCliMetadataRowAssemblyRefOS> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "AssemblyRefOS table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  AssemblyRefOS [" << count++ << "]\n";
        outstream << "    OS platform ID:       " << entry.os_platformID << '\n';
        outstream << "    OS major version:     " << entry.os_major_version << '\n';
        outstream << "    OS minor version:     " << entry.os_minor_version << '\n';
        outstream << "    Assembly Ref:         (Index " << entry.assembly_ref << " into AssemblyRef table)" << '\n';
    }
    outstream << std::endl;
}

void dump_assembly_ref_processor_table(const std::vector<PeCliMetadataRowAssemblyRefProcessor> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "AssemblyRefProcessor table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  AssemblyRefProcessor [" << count++ << "]\n";
        outstream << "    Processor:            " << entry.processor << '\n';
        outstream << "    Assembly Ref:         (Index " << entry.assembly_ref << " into AssemblyRef table)" << '\n';
    }
    outstream << std::endl;
}

void dump_class_layout_table(const std::vector<PeCliMetadataRowClassLayout> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "ClassLayout table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  ClassLayout [" << count++ << "]\n";
        outstream << "    Packing size:         " << entry.packing_size << '\n';
        outstream << "    Class size:           " << entry.class_size << '\n';
        outstream << "    Parent:               (Index " << entry.parent << " into TypeDef table)" << '\n';
    }
    outstream << std::endl;
}

void dump_constant_table(const std::vector<PeCliMetadataRowConstant> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "Constant table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  Constant [" << count++ << "]\n";
        outstream << "    Type:                 " << HexVal{entry.type} << " [";
        // The ECMA-335 spec has a conflict. It list the following values as
        // permissible for the Type column of the Constant table. However it
        // also calls out I1, U2, U4 and U8.
        switch (static_cast<PeCliMetadataElementType>(entry.type))
        {
            case PeCliMetadataElementType::Boolean:
                outstream << "Boolean";
                break;
            case PeCliMetadataElementType::Char:
                outstream << "Char";
                break;
            case PeCliMetadataElementType::I1:
                outstream << "Sbyte (not CLI compliant)";
                break;
            case PeCliMetadataElementType::U1:
                outstream << "Byte";
                break;
            case PeCliMetadataElementType::I2:
                outstream << "Int16";
                break;
            case PeCliMetadataElementType::U2:
                outstream << "UInt32 (not CLI compliant)";
                break;
            case PeCliMetadataElementType::I4:
                outstream << "Int32";
                break;
            case PeCliMetadataElementType::U4:
                outstream << "UInt32 (not CLI compliant";
                break;
            case PeCliMetadataElementType::I8:
                outstream << "Int64";
                break;
            case PeCliMetadataElementType::U8:
                outstream << "UInt64 (not CLI compliant)";
                break;
            case PeCliMetadataElementType::R4:
                outstream << "Single";
                break;
            case PeCliMetadataElementType::R8:
                outstream << "Double";
                break;
            case PeCliMetadataElementType::String:
                outstream << "String";
                break;
            case PeCliMetadataElementType::Class:
                outstream << "Class (";
                if (entry.value == 0)   //TODO: Is this correct or do we have to index the blob and look at what's there???
                    outstream << "Null reference";
                else
                    outstream << "<invalid: value must be zero>";
                outstream << ')';
                break;
            default:
                outstream << "<invalid type>";
                break;
        }
        outstream << "]\n";
        outstream << "    Parent:               0x" << HexVal{entry.parent};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::HasConstant, entry.parent)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
        outstream << "    Value:                " << entry.value << '\n';   // Index into #Blob table
    }
    outstream << std::endl;
}


void dump_custom_attribute_table(const std::vector<PeCliMetadataRowCustomAttribute> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "CustomAttribute table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  Attribute [" << count++ << "]\n";
        outstream << "    Parent:               0x" << HexVal{entry.parent};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::HasCustomAttribute, entry.parent)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";

        outstream << "    Type:                 0x" << HexVal{entry.type};
        table_index = metadata.decode_index(PeCliEncodedIndexType::CustomAttributeType, entry.type);
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";

        outstream << "    Value:                " << entry.value << '\n';   // Index into #Blob table
    }
    outstream << std::endl;
}

void dump_decl_security_table(const std::vector<PeCliMetadataRowDeclSecurity> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "DeclSecurity table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  Entry [" << count++ << "]\n";
        outstream << "    Action:               0x" << HexVal{entry.action} << '\n';    // Haven't yet found sufficient documentation about this table column.
        outstream << "    Parent:               0x" << HexVal{entry.parent};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::HasDeclSecurity, entry.parent)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
        outstream << "    Permission set:       " << entry.permission_set << '\n';  // Index into #Blob table
    }
    outstream << std::endl;
}

void dump_event_table(const std::vector<PeCliMetadataRowEvent> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "Event table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  Event [" << count++ << "]\n";
        outstream << "    Event flags:          0x" << HexVal{entry.event_flags} << '\n';   //TODO: Expand these!!!
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
        outstream << "    Event type:           0x" << HexVal{entry.event_type};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::TypeDefOrRef, entry.event_type)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
    }
    outstream << std::endl;
}

void dump_event_map_table(const std::vector<PeCliMetadataRowEventMap> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "EventMap table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  EventMap [" << count++ << "]\n";
        outstream << "    Parent:               (index " << entry.parent << " into TypeDef table)\n";
        outstream << "    First event:          (index " << entry.event_list << " into Event table)\n";
    }
    outstream << std::endl;
}

void dump_exported_type_table(const std::vector<PeCliMetadataRowExportedType> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "ExportedType table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  ExportedType [" << count++ << "]\n";
        outstream << "    Flags:                0x" << HexVal{entry.flags} << '\n';         //TODO: Expand these!!!
        outstream << "    TypeDef ID:           0x" << HexVal{entry.typedef_id} << '\n';    // This is an index into a TypeDef table in another module in this assembly.
        outstream << "    Type name:            " << metadata.get_string(entry.type_name) << '\n';
        outstream << "    Type namespace:       " << get_metadata_string(metadata, entry.type_namespace) << '\n';
        outstream << "    Implementation:       ";
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::MemberRefParent, entry.implementation)};
        outstream << "(index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
    }
    outstream << std::endl;
}

void dump_field_table(const std::vector<PeCliMetadataRowField> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "Field table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  Field [" << count++ << "]\n";
        outstream << "    Flags:                0x" << HexVal{entry.flags} << '\n';     //TODO Expand these!!!
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
        outstream << "    Signature:            " << entry.signature << '\n';       // Entry into #Blob heap
    }
    outstream << std::endl;
}

void dump_field_layout_table(const std::vector<PeCliMetadataRowFieldLayout> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "FieldLayout table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  FieldLayout [" << count++ << "]\n";
        outstream << "    Offset:               0x" << HexVal{entry.offset} << '\n';
        outstream << "    Field:                (index " << entry.field << " into Field table)\n";
    }
    outstream << std::endl;
}

void dump_field_marshal_table(const std::vector<PeCliMetadataRowFieldMarshal> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "FieldMarshal table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  FieldMarshal [" << count++ << "]\n";
        outstream << "    Parent:               0x" << HexVal{entry.parent};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::HasFieldMarshall, entry.parent)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
        outstream << "    Native type:          " << entry.native_type << '\n';     // Index into #Blob heap
    }
    outstream << std::endl;
}

void dump_field_rva_table(const std::vector<PeCliMetadataRowFieldRVA> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "FieldRVA table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  FieldRVA [" << count++ << "]\n";
        outstream << "    RVA:                  0x" << HexVal{entry.rva} << '\n';
        outstream << "    Field:                (Index " << entry.field << " into Field table)\n";
    }
    outstream << std::endl;
}

void dump_file_table(const std::vector<PeCliMetadataRowFile> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "File table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  File [" << count++ << "]\n";
        outstream << "    Flags:                0x" << HexVal{entry.flags} << '\n';     //TODO: Expand these!!!
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
        outstream << "    Hash value:           " << entry.hash_value << '\n';  // Index into #Blob heap
    }
    outstream << std::endl;
}

void dump_generic_param_table(const std::vector<PeCliMetadataRowGenericParam> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "GenericParam table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  GenericParam [" << count++ << "]\n";
        outstream << "    Number:               " << entry.number << '\n';
        outstream << "    Flags:                0x" << HexVal{entry.flags} << '\n';     //TODO: Expand these!!!
        outstream << "    Owner:                0x" << HexVal{entry.owner};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::TypeOrMethodDef, entry.owner)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
    }
    outstream << std::endl;
}

void dump_generic_param_constraint_table(const std::vector<PeCliMetadataRowGenericParamConstraint> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "GenericParamConstraint table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  GenericParamConstraint [" << count++ << "]\n";
        outstream << "    Owner:                (Index " << entry.owner << " into GenericParam table)\n";
        outstream << "    Constraint:           0x" << HexVal{entry.owner};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::TypeDefOrRef, entry.constraint)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
    }
    outstream << std::endl;
}

void dump_impl_map_table(const std::vector<PeCliMetadataRowImplMap> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "ImplMap table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  ImplMap [" << count++ << "]\n";
        outstream << "    Mapping flags:        0x" << HexVal{entry.mapping_flags} << '\n';   //TODO: Expand these!!!
        outstream << "    Member forwarded:     0x" << HexVal{entry.member_forwarded};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::MemberForwarded, entry.member_forwarded)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
        outstream << "    Import name:          " << metadata.get_string(entry.import_name) << '\n';
        outstream << "    Import scope:         0x" << HexVal{entry.import_scope};
        outstream << " (Index " << entry.import_scope << " into ModuleRef table)";
    }
    outstream << std::endl;
}

void dump_interface_impl_table(const std::vector<PeCliMetadataRowInterfaceImpl> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "InterfaceImpl table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  InterfaceImpl [" << count++ << "]\n";
        outstream << "    Class:                0x" << HexVal{entry.class_};
        outstream << " (Index " << entry.class_ << " into the TypeDef table)\n";
        outstream << "    Interface:            0x" << HexVal{entry.interface_};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::TypeDefOrRef, entry.interface_)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
    }
    outstream << std::endl;
}

void dump_manifest_resource_table(const std::vector<PeCliMetadataRowManifestResource> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "ManifestResource table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  ManifestResource [" << count++ << "]\n";
        outstream << "    Offset                0x" << HexVal{entry.offset} << '\n';
        outstream << "    Flags:                0x" << HexVal{entry.flags} << '\n';   //TODO: Expand these!!!
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
        outstream << "    Implementation:       0x" << HexVal{entry.implementation};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::Implementation, entry.implementation)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
    }
    outstream << std::endl;
}

void dump_member_ref_table(const std::vector<PeCliMetadataRowMemberRef> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "MemberRef table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  MemberRef [" << count++ << "]\n";
        outstream << "    Class:                0x" << HexVal{entry.class_};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::MemberRefParent, entry.class_)};

        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
        outstream << "    Signature             " << entry.signature << '\n';
    }
    outstream << std::endl;
}

void dump_method_def_table(const std::vector<PeCliMetadataRowMethodDef> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "MethodDef table (" << table->size() << " entries)\n";

    size_t  count = 1;

    for (auto &entry : *table)
    {
        outstream << "  MethodDef [" << count++ << "]\n";
        outstream << "    Relative Virtual Address:   0x" << HexVal{entry.rva} << '\n';
        outstream << "    ImplFlags:                  0x" << HexVal{entry.impl_flags} << '\n';  //TODO: Expand these
        outstream << "    Flags:                      0x" << HexVal{entry.flags} << '\n';       //TODO: Expand these
        outstream << "    Name:                       " << metadata.get_string(entry.name) << '\n';
        outstream << "    Signature:                  " << entry.signature << '\n';     // Index into #Blob heap
        outstream << "    First Param:                ";
        if (entry.param_list == 0)
            outstream << "<null>";
        else
            outstream << "(index " << entry.param_list << " into Param table)\n";
    }
    outstream << std::endl;
}

void dump_method_impl_table(const std::vector<PeCliMetadataRowMethodImpl> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "MethodImpl table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  MethodImpl [" << count++ << "]\n";
        outstream << "    Class:                0x" << HexVal{entry.class_};
        outstream << " (Index " << entry.class_ << " into TypeDef table)\n";

        outstream << "    Method body:          0x" << HexVal{entry.method_body};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::MethodDefOrRef, entry.method_body)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";

        outstream << "    Method declaration:   0x" << HexVal{entry.method_declaration};
        table_index = metadata.decode_index(PeCliEncodedIndexType::MethodDefOrRef, entry.method_declaration);
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
    }
    outstream << std::endl;
}

void dump_method_semantics_table(const std::vector<PeCliMetadataRowMethodSemantics> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "MethodSemantics table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  MethodSemantics [" << count++ << "]\n";
        outstream << "    Semantics:            0x" << HexVal{entry.semantics} << '\n';     //TODO: Expand these!!!
        outstream << "    Method:               0x" << HexVal{entry.method};
        outstream << " (index " << entry.method << " into MethodDef table)\n";
        outstream << "    Association:          0x" << HexVal{entry.association};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::HasSemantics, entry.association)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
    }
    outstream << std::endl;
}

void dump_method_spec_table(const std::vector<PeCliMetadataRowMethodSpec> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "MethodSpec table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  MethodSpec [" << count++ << "]\n";
        outstream << "    Method:               0x" << HexVal{entry.method};
        PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::MethodDefOrRef, entry.method)};
        outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";

        outstream << "   Instantiation:         " << entry.instantiation << '\n';   // Index into the #Blob heap
    }
    outstream << std::endl;
}

void dump_module_table(const std::vector<PeCliMetadataRowModule> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "Module table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  Module [" << count++ << "]\n";
        outstream << "    Generation:           " << entry.generation << '\n';
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
        outstream << "    Mvid:                 " << guid_to_string(metadata.get_guid(entry.mv_id)) << '\n';
        outstream << "    EncId: <reserved>     " << entry.enc_id << '\n';
        outstream << "    EncBaseId: <reserved> " << entry.enc_base_id << '\n';
    }
    outstream << std::endl;
}

void dump_module_ref_table(const std::vector<PeCliMetadataRowModuleRef> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "ModuleRef table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  ModuleRef [" << count++ << "]\n";
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
    }
    outstream << std::endl;
}

void dump_nested_class_table(const std::vector<PeCliMetadataRowNestedClass> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "NestedClass table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  NestedClass [" << count++ << "]\n";
        outstream << "    Nested class:         0x" << HexVal{entry.nested_class};
        outstream << " (index " << entry.nested_class << " into TypeDef table)\n";
        outstream << "    Enclosing class:      0x" << HexVal{entry.enclosing_class};
        outstream << " (index " << entry.enclosing_class << " into TypeDef table)\n";
    }
    outstream << std::endl;
}

void dump_param_table(const std::vector<PeCliMetadataRowParam> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "Param table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  Param [" << count++ << "]\n";
        outstream << "    Flags:                0x" << HexVal{entry.flags} << '\n';     //TODO: Expand these!!!
        outstream << "    Sequence:             0x" << HexVal{entry.sequence} << '\n';
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
    }
    outstream << std::endl;
}

void dump_property_table(const std::vector<PeCliMetadataRowProperty> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "Property table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  Property [" << count++ << "]\n";
        outstream << "    Flags:                0x" << HexVal{entry.flags} << '\n';     //TODO: Expand these!!!
        outstream << "    Name:                 " << metadata.get_string(entry.name) << '\n';
        outstream << "    Type (signature):     " << entry.type << '\n';    // Index into #Blob heap
    }
    outstream << std::endl;
}

void dump_property_map_table(const std::vector<PeCliMetadataRowPropertyMap> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "PropertyMap table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  PropertyMap [" << count++ << "]\n";
        outstream << "    Parent:               0x" << HexVal{entry.parent};
        outstream << " (index " << entry.parent << " into TypeDef table)\n";
        outstream << "    First Property:       0x" << HexVal{entry.property_list};
        outstream << " (index " << entry.parent << " into Property table)\n";
    }
    outstream << std::endl;
}

void dump_standalone_sig_table(const std::vector<PeCliMetadataRowStandAloneSig> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "StandaloneSig table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  StandaloneSig [" << count++ << "]\n";
        outstream << "    Signature:            " << entry.signature << '\n';    // Index into #Blob heap
    }
    outstream << std::endl;
}

void write_type_attributes(uint32_t flags, std::ostream &outstream)
{
    enum TypeAttributes : uint32_t
    {
        VisibilityMask          = 0x00000007,
        NotPublic               = 0x00000000,
        Public                  = 0x00000001,
        NestedPublic            = 0x00000002,
        NestedPrivate           = 0x00000003,
        NestedFamily            = 0x00000004,
        NestedAssembly          = 0x00000005,
        NestedFamANDAssem       = 0x00000006,
        NestedFamORAssem        = 0x00000007,

        LayoutMask              = 0x00000018,
        AutoLayout              = 0x00000000,
        SequentialLayout        = 0x00000008,
        ExplicitLayout          = 0x00000010,

        ClassSemanticsMask      = 0x00000020,
        Class                   = 0x00000000,
        Interface               = 0x00000020,

        Abstract                = 0x00000080,
        Sealed                  = 0x00000100,
        SpecialName             = 0x00000400,
        Import                  = 0x00001000,
        Serializable            = 0x00002000,

        StringFormatMask        = 0x00030000,
        AnsiClass               = 0x00000000,   // LPSTR is interpreted as ANSI
        UnicodeClass            = 0x00010000,   // LPSTR is interpreted as Unicode
        AutoClass               = 0x00020000,   // LPSTR is interpreted automatically
        CustomFormatClass       = 0x00030000,   // A non-standard encoding specified by CustomStringFormatMask
        CustomStringFormatMask  = 0x00C00000,   // Mask to retrieve non-standard encoding information for native interop.
                                                // The meaning of the values of these 2 bits is unspecified.
        BeforeFieldInit         = 0x00100000,
        RTSpecialName           = 0x00000800,
        HasSecurity             = 0x00040000,
        IsTypeForwarder         = 0x00200000
    };

    switch (flags & VisibilityMask)
    {
        case NotPublic:
            outstream << "NotPublic";
            break;
        case Public:
            outstream << "Public";
            break;
        case NestedPublic:
            outstream << "NestedPublic";
            break;
        case NestedPrivate:
            outstream << "NestedPrivate";
            break;
        case NestedFamily:
            outstream << "NestedFamily";
            break;
        case NestedAssembly:
            outstream << "NestedAssembly";
            break;
        case NestedFamANDAssem:
            outstream << "NestedFamANDAssem";
            break;
        case NestedFamORAssem:
            outstream << "NestedFamORAssm";
            break;
    }

    switch (flags & LayoutMask)
    {
        case AutoLayout:
            outstream << " AutoLayout";
            break;
        case SequentialLayout:
            outstream << " SequentialLayout";
            break;
        case ExplicitLayout:
            outstream << " ExplicitLayout";
            break;
    }

    switch (flags & ClassSemanticsMask)
    {
        case Class:
            outstream << " Class";
            break;
        case Interface:
            outstream << " Interface";
            break;
    }

    if (flags & Abstract)
        outstream << " Abstract";
    if (flags & Sealed)
        outstream << " Sealed";
    if (flags & SpecialName)
        outstream << " SpecialName";
    if (flags & Import)
        outstream << " Import";
    if (flags & Serializable)
        outstream << " Serializable";

    switch (flags & StringFormatMask)
    {
        case AnsiClass:
            outstream << " AnsiClass";
            break;
        case UnicodeClass:
            outstream << " UnicodeClass";
            break;
        case AutoClass:
            outstream << " AutoClass";
            break;
        case CustomFormatClass:
            outstream << " CustomFormatClass";
            break;
    }

    if (flags & BeforeFieldInit)
        outstream << " BeforeFieldInit";
    if (flags & RTSpecialName)
        outstream << " RTSpecialName";
    if (flags & HasSecurity)
        outstream << " HasSecurity";
    if (flags & IsTypeForwarder)
        outstream << " IsTypeForwarder";
}

void dump_type_def_table(const std::vector<PeCliMetadataRowTypeDef> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "TypeDef table (" << table->size() << " entries)\n";

    size_t  count = 1;

    for (auto &entry : *table)
    {
        outstream << "  TypeDef [" << count++ << "]\n";
        outstream << "    Flags:                      0x" << HexVal{entry.flags} << " [";
        write_type_attributes(entry.flags, outstream);
        outstream << "]\n";
        outstream << "    Type name:                  " << metadata.get_string(entry.type_name) << '\n';                // Must index a non-empty string
        outstream << "    Namespace name:             " << get_metadata_string(metadata, entry.type_namespace) << '\n'; // Could be a null index (0)
        outstream << "    Extends:                    ";

        // Extends may be null only when defining the special type "<Module>" type.
        // Everything else must extend at least System.Object
        if (entry.extends == 0)
        {
            outstream << "<null>\n";
        }
        else
        {
            PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::TypeDefOrRef, entry.extends)};
            outstream << "(index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
        }

        //TODO: Handle indexes outside the range of the table!!!
        // Some index columns may contain a value that is larger than the
        // specified number of rows in the indexed table, or even a non-zero
        // index into a table that does not exist in the metadata. For some
        // indexes a valid value is in the range 1 <= row <= rowcount+1.
        // A TypeDef entry's field_list and method_list columns exhibit this
        // behavior. This code does not yet deal with this occurrence.
        outstream << "    First Field:                ";
        if (entry.field_list == 0)
            outstream << "<null>";
        else
            outstream << "(index " << entry.field_list << " into Field table)\n";

        outstream << "    First Method:               ";
        if (entry.method_list == 0)
            outstream << "<null>";
        else
            outstream << "(index " << entry.method_list << " into MethodDef table)\n";
    }
    outstream << std::endl;
}

void dump_type_ref_table(const std::vector<PeCliMetadataRowTypeRef> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "TypeRef table (" << table->size() << " entries)\n";

    size_t  count = 1;

    for (auto &entry : *table)
    {
        outstream << "  TypeRef [" << count++ << "]\n";
        outstream << "    Resolution scope:           0x" << HexVal{entry.resolution_scope};
        if (entry.resolution_scope != 0)
        {
            // The ResolutionScope column in the TypeRef table can index into one of several table types.
            // The index and the specific table are encoded into a single value. The decode_index function
            // decodes that value into a small structure. This is a common occurrence in the metadata tables.
            PeCliMetadataTableIndex table_index{metadata.decode_index(PeCliEncodedIndexType::ResolutionScope, entry.resolution_scope)};

            outstream << " (index " << table_index.index << " into " << get_table_type_name(table_index.table_id) << " table)\n";
        }
        else
        {
            outstream << '\n';
        }
        outstream << "    Type name:                  " << metadata.get_string(entry.type_name) << '\n';                // Must index a non-empty string
        outstream << "    Namespace name:             " << get_metadata_string(metadata, entry.type_namespace) << '\n'; // Could be a null index (0)
    }
    outstream << std::endl;
}

void dump_type_spec_table(const std::vector<PeCliMetadataRowTypeSpec> *table, const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "TypeSpec table (" << table->size() << " entries)\n";

    size_t  count = 1;
    for (auto &entry : *table)
    {
        outstream << "  TypeSpec [" << count++ << "]\n";
        outstream << "    Signature:            " << entry.signature << '\n';    // Index into #Blob heap
    }
    outstream << std::endl;
}

void dump_cli_metadata_tables(const PeCli &cli, std::ostream &outstream)
{
    outstream << "CLI Metadata Tables\n-------------------------------------------\n";

    if (cli.metadata() && cli.metadata()->metadata_tables())
    {
        const auto *ptables{cli.metadata()->metadata_tables()};
        const auto &header{ptables->header()};

        outstream << "Header:" << '\n';
        outstream << "    reserved:      " << header.reserved0 << '\n';
        outstream << "    Major version: " << static_cast<uint16_t>(header.major_version) << '\n';
        outstream << "    Minor version: " << static_cast<uint16_t>(header.minor_version) << '\n';
        outstream << "    Heap sizes:    0x" << HexVal(header.heap_sizes) << '\n';      // bit field, not a count
        outstream << "    reserved:      " << static_cast<uint16_t>(header.reserved1) << '\n';
        outstream << "    Valid tables:  0x" << HexVal(header.valid_tables) << '\n';    // bit field, not a count
        outstream << "    Sorted tables: 0x" << HexVal(header.sorted_tables) << '\n';   // bit field, not a count

        outstream << "\nAvailable tables:\n";
        outstream << "---------------------------------------\n  Table                          Rows\n---------------------------------------\n";
        for (size_t i = 0; i < ptables->valid_table_types().size(); ++i)
            outstream << "  " << std::left << std::setw(25)
                              << get_table_type_name(ptables->valid_table_types()[i])
                              << std::right << std::setw(10) << ptables->header().row_counts[i] << '\n';
        outstream << std::endl;


        for (auto &table_type : ptables->valid_table_types())
        {
            switch (table_type)
            {
                case PeCliMetadataTableId::Assembly:
                    dump_assembly_table(ptables->assembly_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::AssemblyOS:
                    dump_assembly_os_table(ptables->assembly_os_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::AssemblyProcessor:
                    dump_assembly_processor_table(ptables->assembly_processor_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::AssemblyRef:
                    dump_assembly_ref_table(ptables->assembly_ref_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::AssemblyRefOS:
                    dump_assembly_ref_os_table(ptables->assembly_ref_os_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::AssemblyRefProcessor:
                    dump_assembly_ref_processor_table(ptables->assembly_ref_processor_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::ClassLayout:
                    dump_class_layout_table(ptables->class_layout_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::Constant:
                    dump_constant_table(ptables->constant_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::CustomAttribute:
                    dump_custom_attribute_table(ptables->custom_attribute_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::DeclSecurity:
                    dump_decl_security_table(ptables->decl_security_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::Event:
                    dump_event_table(ptables->event_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::EventMap:
                    dump_event_map_table(ptables->event_map_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::ExportedType:
                    dump_exported_type_table(ptables->exported_type_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::Field:
                    dump_field_table(ptables->field_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::FieldLayout:
                    dump_field_layout_table(ptables->field_layout_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::FieldMarshal:
                    dump_field_marshal_table(ptables->field_marshal_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::FieldRVA:
                    dump_field_rva_table(ptables->field_rva_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::File:
                    dump_file_table(ptables->file_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::GenericParam:
                    dump_generic_param_table(ptables->generic_param_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::GenericParamConstraint:
                    dump_generic_param_constraint_table(ptables->generic_param_constraint_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::ImplMap:
                    dump_impl_map_table(ptables->impl_map_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::InterfaceImpl:
                    dump_interface_impl_table(ptables->interface_impl_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::ManifestResource:
                    dump_manifest_resource_table(ptables->manifest_resource_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::MemberRef:
                    dump_member_ref_table(ptables->member_ref_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::MethodDef:
                    dump_method_def_table(ptables->method_def_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::MethodImpl:
                    dump_method_impl_table(ptables->method_impl_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::MethodSemantics:
                    dump_method_semantics_table(ptables->method_semantics_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::MethodSpec:
                    dump_method_spec_table(ptables->method_spec_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::Module:
                    dump_module_table(ptables->module_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::ModuleRef:
                    dump_module_ref_table(ptables->module_ref_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::NestedClass:
                    dump_nested_class_table(ptables->nested_class_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::Param:
                    dump_param_table(ptables->param_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::Property:
                    dump_property_table(ptables->property_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::PropertyMap:
                    dump_property_map_table(ptables->property_map_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::StandAloneSig:
                    dump_standalone_sig_table(ptables->standalone_sig_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::TypeDef:
                    dump_type_def_table(ptables->type_def_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::TypeRef:
                    dump_type_ref_table(ptables->type_ref_table(), *cli.metadata(), outstream);
                    break;
                case PeCliMetadataTableId::TypeSpec:
                    dump_type_spec_table(ptables->type_spec_table(), *cli.metadata(), outstream);
                    break;
            }
        }
        const auto *modules{ptables->module_table()};
    }
}

void dump_cli_metadata(const PeCliMetadata &metadata, std::ostream &outstream)
{
    outstream << "CLI Metadata\n-------------------------------------------\n";

    const PeCliMetadataHeader  &header{metadata.header()};

    outstream << "Metadata Header\n";
    outstream << "    Signature:      0x" << HexVal(header.signature) << '\n';
    outstream << "    Major version:  " << header.major_version << '\n';
    outstream << "    Minor version:  " << header.minor_version << '\n';
    outstream << "    reserved:       " << header.reserved << '\n';
    outstream << "    Version length: " << header.version_length << '\n';
    outstream << "    Version string: " << header.version << '\n';
    outstream << "    Flags:          0x" << HexVal(header.flags) << '\n';
    //TODO: Dump flags!!!
    outstream << "    Stream count    " << header.stream_count << '\n' << std::endl;

    outstream << "Heap streams:\n";
    for (auto &hdr : metadata.stream_headers())
    {
        outstream << "    Stream: " << hdr.name << '\n';
        outstream << "      Offset:       " << hdr.offset << '\n';
        outstream << "      Size:         " << hdr.size << '\n';

        if (metadata.has_streams())
        {
            const auto *pstream{metadata.get_stream(hdr.name)};

            if (pstream)
                outstream << HexDump(pstream->data(), pstream->size()) << '\n';
        }
    }
}

void dump_cli(const PeCli &cli, std::ostream &outstream)
{
    outstream << "CLI Information (Appears to be managed code)\n-------------------------------------------\n";

    outstream << "CLI portion begins at offset " << HexVal(cli.file_offset()) << ", in the " << cli.section().header().name << " section\n";

    const PeCliHeader  &header{cli.header()};

    outstream << "CLI Header:\n";
    outstream << "    Size: " << header.size << '\n';
    outstream << "    Major runtime version: " << header.major_runtime_version << '\n';
    outstream << "    Minor runtime version: " << header.minor_runtime_version << '\n';
    outstream << "    Flags:                 0x" << HexVal(header.flags) << '\n';
    if (header.flags & PeCliEntryPointFlags::IlOnly)
        outstream << "      IL only" << '\n';
    if (header.flags & PeCliEntryPointFlags::Required32Bit)
        outstream << "      32-bit required" << '\n';
    if (header.flags & PeCliEntryPointFlags::IlLibrary)
        outstream << "      IL library" << '\n';
    if (header.flags & PeCliEntryPointFlags::StrongNameSigned)
        outstream << "      String name signed" << '\n';
    if (header.flags & PeCliEntryPointFlags::NativeEntryPoint)
        outstream << "      Native entry point" << '\n';
    if (header.flags & PeCliEntryPointFlags::TrackDebugData)
        outstream << "      Track debug data" << '\n';
    if (header.flags & PeCliEntryPointFlags::Preferred32Bit)
        outstream << "      32-bit preferred" << '\n';
    if (header.flags & PeCliEntryPointFlags::NativeEntryPoint)
        outstream << "    Entry point RVA:       0x" << HexVal(header.entry_point_RVA) << '\n';
    else
        outstream << "    Entry point token:     0x" << HexVal(header.entry_point_token) << '\n';
    outstream << "    Virtual addresses:\n";
    outstream << "      Metadata:\n";
    outstream << "        RVA:  0x" << HexVal(header.metadata.virtual_address) << '\n';
    outstream << "        Size:   " << std::setw(8) << header.metadata.size << '\n';
    outstream << "      Resources:\n";
    outstream << "        RVA:  0x" << HexVal(header.resources.virtual_address) << '\n';
    outstream << "        Size:   " << std::setw(8) << header.resources.size << '\n';
    outstream << "      Strong name signature:\n";
    outstream << "        RVA:  0x" << HexVal(header.strong_name_signature.virtual_address) << '\n';
    outstream << "        Size:   " << std::setw(8) << header.strong_name_signature.size << '\n';
    outstream << "      Code manager table:\n";
    outstream << "        RVA:  0x" << HexVal(header.code_manager_table.virtual_address) << '\n';
    outstream << "        Size:   " << std::setw(8) << header.code_manager_table.size << '\n';
    outstream << "      vtable fixups:\n";
    outstream << "        RVA:  0x" << HexVal(header.vtable_fixups.virtual_address) << '\n';
    outstream << "        Size:   " << std::setw(8) << header.vtable_fixups.size << '\n';
    outstream << "      Export address table jumps:\n";
    outstream << "        RVA:  0x" << HexVal(header.export_address_table_jumps.virtual_address) << '\n';
    outstream << "        Size:   " << std::setw(8) << header.export_address_table_jumps.size << '\n';
    outstream << "      Managed native header:\n";
    outstream << "        RVA:  0x" << HexVal(header.managed_native_header.virtual_address) << '\n';
    outstream << "        Size:   " << std::setw(8) << header.managed_native_header.size << '\n' << std::endl;

    if (cli.has_metadata())
    {
        dump_cli_metadata(*cli.metadata(), outstream);
        if (cli.metadata()->has_tables())
            dump_cli_metadata_tables(cli, outstream);
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

    if (info.has_exports())
    {
        dump_exports_table(*info.exports(), outstream);
        outstream << separator << std::endl;
    }

    if (info.has_imports())
    {
        dump_imports_table(*info.imports(), outstream);
        outstream << separator << std::endl;
    }

    if (!info.debug_directory().empty())
    {
        dump_debug_directory(info.debug_directory(), outstream);
        outstream << separator << std::endl;
    }

    if (info.optional_header_32())
        dump_sections(info.sections(), info.optional_header_32()->image_base, outstream);
    else
        dump_sections(info.sections(), info.optional_header_64()->image_base, outstream);
    outstream << separator << std::endl;

    if (info.has_cli())
    {
        dump_cli(*info.cli(), outstream);
    }
}
