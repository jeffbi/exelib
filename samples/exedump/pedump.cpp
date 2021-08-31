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
       << '-' << HexVal{*(p + 2)} << HexVal{*(p + 3)} << HexVal{*(p + 4)} << HexVal{*(p + 5)}
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
    outstream << "Timestamp              0x" << HexVal{header.timestamp} << ' ' << format_timestamp(header.timestamp) << '\n';
    outstream << "Symbol Table offset:   0x" << HexVal{header.symbol_table_offset} << '\n';
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
}
