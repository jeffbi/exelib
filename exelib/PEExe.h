/// \file   PEExe.h
/// Classes and structures describing the PE section of a Portable Executable
/// format executable.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_PEEXE_H_
#define _EXELIB_PEEXE_H_

#include <cstdint>
#include <cstring>
#include <iosfwd>
#include <iterator>
#include <memory>
#include <utility>
#include <vector>

#include "LoadOptions.h"

/// \brief  Describes the PE-style header
struct PeImageFileHeader
{
    uint32_t	signature;				// PE\0\0 = 0x00004550
    uint16_t	target_machine;			// number that identifies the type of target machine; see MachineType enum
    uint16_t	num_sections;			// number of sections in the Section Table
    uint32_t	timestamp;				// unix-style timestamp indicating when the file was created.
    uint32_t	symbol_table_offset;	// offset of the Symbol Table; zero indicats no symbol table is present
    uint32_t	num_symbols;			// number of entries in the Symbol Table
    uint16_t	optional_header_size;	// size of the optional header; will be zero for an object file
    uint16_t	characteristics;		// flags indicating the attributes of the file

    static constexpr uint32_t   pe_signature{0x00004550};

    enum Characteristics
    {
        RelocsStripped          = 0x0001,   // image only; WinCE and NT and higher; indicates the file does not contain base relocations and must therefore be loaded at its preferred base address.
        ExecutableImage         = 0x0002,   // image only; indicates the image file is valid and can be run; if not set, indicates a linker error.
        LineNumsStripped        = 0x0004,   // COFF line numbers have been removed. This flag is deprecated and should be zero.
        LocalSymsStripped       = 0x0008,   // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
        AggressiveWsTrim        = 0x0010,   // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
        LargeAddressAware       = 0x0020,   // Application can handle > 2 GB addresses.
        //                      = 0x0040,   // This flag is reserved for future use.
        BytesReversedLO         = 0x0080,   // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
        Machine32Bit            = 0x0100,   // Machine is based on a 32-bit-word architecture.
        DebugStripped           = 0x0200,   // Debugging information is removed from the image file.
        RemovableRunFromSwap    = 0x0400,   // If the image is on removable media, fully load it and copy it to the swap file.
        NetRunFromSwap          = 0x0800,   // If the image is on network media, fully load it and copy it to the swap file.
        System                  = 0x1000,   // The image file is a system file, not a user program.
        DLL                     = 0x2000,   // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
        UPSystemOnly	        = 0x4000,   // The file should be run only on a uniprocessor machine.
        BytesReversedHI	        = 0x8000    // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    };
};

enum class PeMachineType : uint16_t
{
    Unknown     = 0x0000,   // The contents of this field are assumed to be applicable to any machine type
    AM33        = 0x01D3,   // Matsushita AM33
    AMD64       = 0x8664,   // x64
    ARM         = 0x01C0,   // ARM little endian
    ARM64       = 0xAA64,   // ARM64 little endian
    ARMNT       = 0x01C4,   // ARM Thumb-2 little endian
    EBC         = 0x0EBC,   // EFI byte code
    I386        = 0x014C,   // Intel 386 or later processors and compatible processors
    IA64        = 0x0200,   // Intel Itanium processor family
    M32R        = 0x9041,   // Mitsubishi M32R little endian
    MIPS16      = 0x0266,   // MIPS16
    MIPSFPU     = 0x0366,   // MIPS with FPU
    MIPSFPU16   = 0x0466,   // MIPS16 with FPU
    PowerPC     = 0x01F0,   // Power PC little endian
    PowerPCFP   = 0x01F1,   // Power PC with floating point support
    R4000       = 0x0166,   // MIPS little endian
    RISCV32     = 0x5032,   // RISC-V 32-bit address space
    RISCV64     = 0x5064,   // RISC-V 64-bit address space
    RISCV128    = 0x5128,   // RISC-V 128-bit address space
    SH3         = 0x01A2,   // Hitachi SH3
    SH3DSP      = 0x01A3,   // Hitachi SH3 DSP
    SH4         = 0x01A6,   // Hitachi SH4
    SH5         = 0x01A8,   // Hitachi SH5
    Thumb       = 0x01C2,   // Thumb
    WCEMIPSv2   = 0x0169    // MIPS little-endian WCE v2
};

struct PeOptionalHeaderBase
{
    uint16_t magic;                 // 0x010B - PE32, 0x020B - PE32+ (64 bit)
    uint8_t  linker_version_major;
    uint8_t  linker_version_minor;
    uint32_t code_size;
    uint32_t initialized_data_size;
    uint32_t uninitialized_data_size;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
};

struct PeOptionalHeader32 : public PeOptionalHeaderBase
{
    uint32_t base_of_data;
    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t os_version_major;
    uint16_t os_version_minor;
    uint16_t image_version_major;
    uint16_t image_version_minor;
    uint16_t subsystem_version_major;
    uint16_t subsystem_version_minor;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t num_rva_and_sizes;
};

struct PeOptionalHeader64 : public PeOptionalHeaderBase
{
    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t os_version_major;
    uint16_t os_version_minor;
    uint16_t image_version_major;
    uint16_t image_version_minor;
    uint16_t subsystem_version_major;
    uint16_t subsystem_version_minor;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t num_rva_and_sizes;
};

enum class PeSubsystem : uint16_t
{
    Unknown                 = 0,    // An unknown subsystem
    Native                  = 1,    // Device drivers and native Windows processes
    Windows_GUI             = 2,    // The Windows graphical user interface (GUI) subsystem
    Windows_CUI             = 3,    // The Windows character subsystem
    OS2_CUI                 = 5,    // The OS/2 character subsystem
    Posix_CUI               = 7,    // The Posix character subsystem
    NativeWindows           = 8,    // Native Win9x driver
    WindowsCE_GUI           = 9,    // Windows CE
    EfiApplication          = 10,   // An Extensible Firmware Interface (EFI) application
    EfiBootServiceDriver    = 11,   // An EFI driver with boot services
    EfiRuntimeDriver        = 12,   // An EFI driver with run-time services
    EfiROM                  = 13,   // An EFI ROM image
    XBox                    = 14,   // Xbox
    WindowsBootApplication  = 16,   // Windows boot application
    XBoxCodeCatalog         = 17    // Xbox code catalog
};

enum class PeDllCharacteristics : uint16_t
{
    HighEntropyVA       = 0x0020,   // Image can handle a high entropy 64-bit virtual address space
    DynamicBase         = 0x0040,   // DLL can be relocated at load time
    ForceIntegrity      = 0x0080,   // Code Integrity checks are enforced
    NxCompatible        = 0x0100,   // Image is NX compatible
    NoIsolation         = 0x0200,   // Isolation aware, but do not isolate the image
    NoSEH               = 0x0400,   // Does not use structured exception handling
    NoBind              = 0x0800,   // Do not bind the image
    AppContainer        = 0x1000,   // Image must execute in an AppContainer
    WmdDriver           = 0x2000,   // A WMD driver
    ControlFlowGuard    = 0x4000,   // Image supports Control Flow Guard
    TerminalServerAware = 0x8000    // Terminal server aware
};

struct PeDataDirectoryEntry
{
    uint32_t    virtual_address;
    uint32_t    size;
};

struct PeSectionHeader
{
    uint8_t     name[8];                    // eight bytes of UTF-8 encoded name data
    uint32_t    virtual_size;
    uint32_t    virtual_address;
    uint32_t    size_of_raw_data;
    uint32_t    raw_data_position;
    uint32_t    relocations_position;
    uint32_t    line_numbers_position;
    uint16_t    number_of_relocations;
    uint16_t    number_of_line_numbers;
    uint32_t    characteristics;
};

enum class PeSectionHeaderCharacteristics : uint32_t
{
    //                  = 0x00000000,   // reserved
    //                  = 0x00000001,   // reserved
    //                  = 0x00000002,   // reserved
    //                  = 0x00000004,   // reserved
    NoPadding           = 0x00000008,   // Section should not be padded to the next boundary. Object files only. Obsolete
    //                  = 0x00000010,   // reserved
    ExecutableCode      = 0x00000020,   // Section contains executable code
    InitializedData     = 0x00000040,   // Section contains initialized data
    UninitializedData   = 0x00000080,   // Section contains unitialized data
    LinkOther           = 0x00000100,   // reserved
    LinkInfo            = 0x00000200,   // Section contains comments or other information. Object files only.
    //                  = 0x00000400,   // reserved
    LinkRemove          = 0x00000800,   // Section will not become part of the image. Object files only.
    LinkCOMDAT          = 0x00001000,   // Section contains COMDAT data. Object files only.
    GlobalPointerData   = 0x00008000,   // Section contains data referenced through the Global Pointer
    MemPurgable         = 0x00020000,   // reserved
    Mem16Bit            = 0x00020000,   // reserved
    MemLocked           = 0x00040000,   // reserved
    MemPreload          = 0x00080000,   // reserved
    Align1Bytes         = 0x00100000,   // Align data on a 1-byte boundary. Object files only.
    Align2Bytes         = 0x00200000,   // Align data on a 2-byte boundary. Object files only.
    Align4Bytes         = 0x00300000,   // Align data on a 4-byte boundary. Object files only.
    Align8Bytes         = 0x00400000,   // Align data on a 8-byte boundary. Object files only.
    Align16Bytes        = 0x00500000,   // Align data on a 16-byte boundary. Object files only.
    Align32Bytes        = 0x00600000,   // Align data on a 32-byte boundary. Object files only.
    Align64Bytes        = 0x00700000,   // Align data on a 64-byte boundary. Object files only.
    Align128Bytes       = 0x00800000,   // Align data on a 128-byte boundary. Object files only.
    Align256Bytes       = 0x00900000,   // Align data on a 256-byte boundary. Object files only.
    Align512Bytes       = 0x00A00000,   // Align data on a 512-byte boundary. Object files only.
    Align1024Bytes      = 0x00B00000,   // Align data on a 1024-byte boundary. Object files only.
    Align2048Bytes      = 0x00C00000,   // Align data on a 2048-byte boundary. Object files only.
    Align4096Bytes      = 0x00D00000,   // Align data on a 4096-byte boundary. Object files only.
    Align8192Bytes      = 0x00E00000,   // Align data on a 8192-byte boundary. Object files only.
    AlignMask           = 0x00F00000,
    LinkNRelocOverflow  = 0x01000000,   // Section contains extended relocations
    MemDiscardable      = 0x02000000,   // Section can be discarded
    MemNotCached        = 0x04000000,   // Section cannot be cached
    MemNotPaged         = 0x08000000,   // Section is not pageable
    MemShared           = 0x10000000,   // Section can be shared in memory
    MemExecute          = 0x20000000,   // Section can be executed as code
    MemRead             = 0x40000000,   // Section can be read
    MemWrite            = 0x80000000    // Section can be written to
};

class PeSection
{
public:
    PeSection(const PeSectionHeader &header, std::vector<uint8_t> &&data)
        : _header{header}
        , _data{data}
        , _data_loaded{true}
    {}

    PeSection(const PeSectionHeader &header, const std::vector<uint8_t> &data)
        : _header{header}
        , _data{data}
        , _data_loaded{true}
    {}

    PeSection(const PeSectionHeader &header)
        :_header{header}
        , _data_loaded{false}
    {}

    PeSection() = delete;
    PeSection(const PeSection &other) = default;
    PeSection(PeSection &&other) = default;
    PeSection &operator=(const PeSection &other) = default;
    PeSection &operator=(PeSection &&other) = default;

    /// \brief  Return a value indicating whether the section's raw data was loaded.
    ///
    /// It is conceiveably possible that a section may have zero-length data,
    /// in which case the object's data container will be empty, just as if
    /// no data had been loaded. This function can be used to get a more
    /// definitive answer to whether data was loaed.
    bool data_loaded() const noexcept
    {
        return _data_loaded;
    }

    /// \brief  Return a reference to the raw data container.
    const std::vector<uint8_t> &data() const noexcept
    {
        return _data;
    }

    /// \brief  Return a reference to the section header.
    const PeSectionHeader &header() const noexcept
    {
        return _header;
    }

    /// \brief  Convenience function to return the section's virtual address.
    ///
    /// This address is relative to the executable's base address. Add this
    /// value to the executable's base address, which can be accessed through
    /// the PE Optional Header, to get the complete virtual address.
    uint32_t virtual_address() const noexcept
    {
        return _header.virtual_address;
    }

    /// \brief  Convenience function to return the section's virtual size.
    uint32_t virtual_size() const noexcept
    {
        return _header.virtual_size;
    }

    /// \brief  Convenience function to return the section's raw data size.
    uint32_t raw_data_size() const noexcept
    {
        return _header.size_of_raw_data;
    }

    /// \brief  Return the usable size of the section data, which is the
    ///         smaller of \c virtual_size() or \c raw_data_size().
    uint32_t size() const noexcept
    {
        return std::min(virtual_size(), raw_data_size());
    }

private:
    PeSectionHeader         _header;
    std::vector<uint8_t>    _data;
    bool                    _data_loaded;
};

/// \brief  Describes the Export Directory Table.
///
/// The Export Directory Table contains a single "row" of data
/// describing the rest of the export symbol information.
struct PeExportDirectory
{
    uint32_t    export_flags;               /// Reserved, must be zero.
    uint32_t    timestamp;                  /// Date and time the export data was created.
    uint16_t    version_major;              /// Major version number.
    uint16_t    version_minor;              /// Minor version number.
    uint32_t    name_rva;                   /// RVA of the ASCII string containing the name of the DLL.
    uint32_t    ordinal_base;               /// Starting ordinal number for exports in this image. Usually set to 1.
    uint32_t    num_address_table_entries;  /// Number of entries in the Export Address Table.
    uint32_t    num_name_pointers;          /// Number of entries in the Name Pointer Table, and in the ordinals table.
    uint32_t    export_address_rva;         /// RVA of the Export Address Table.
    uint32_t    name_pointer_rva;           /// RVA of the Export Name Pointer Table.
    uint32_t    ordinal_table_rva;          /// RVA of the Export Ordinal Table.
};


// For the moment I'm not going to attempt to load the forwarder
// strings. I have found at least one DLL for which this code
// does not work. In that DLL, The alorithm for determining if
// the export is a forward reference does not work properly.
//
// This may have something to do with the export tables in
// this DLL being contained in the .text section. Microsoft's
// documentation says that exported code or data is expected to
// reside in a different section than the one that the export
// table is in, but code, exported or not, generally also
// resides in the .text section.
//
// I'm still tracking this down. In the meantime the preprocessor
// symbol below should remain defined.

#define EXELIB_NO_LOAD_FORWARDERS    // Keep this defined until I can track down an issue with forwarder strings.
struct PeExportAddressTableEntry
{
    uint32_t    export_rva;     /// RVA of the exported symbol or to a forwarder string.
    // The above is what's in the file.
#if !defined(EXELIB_NO_LOAD_FORWARDERS)
    bool        is_forwarder;
    std::string forwarder_name; /// The forwarder name, extracted via \c export_rva.
#endif
};

struct PeExports
{
    using AddressTable      = std::vector<PeExportAddressTableEntry>;
    using NamePointerTable  = std::vector<uint32_t>;
    using OrdinalTable      = std::vector<uint16_t>;
    using NameTable         = std::vector<std::string>;

    PeExportDirectory       directory;          /// Exports info including addresses of tables
    std::string             name;               /// Name of the DLL, extracted via \c directory.name_rva.
    AddressTable            address_table;      /// Collection of Address Table entries.

#if !defined(EXELIB_NO_LOAD_FORWARDERS)
    std::vector<uint32_t>   forward_indices;    /// Collection of indexes into the Address Table for forwarders
#endif
        //TODO: consider merging the next
        //      three items into a single
        //      collection!!!
    NamePointerTable        name_pointer_table; /// Collection of RVAs into the Export Name Table
    OrdinalTable            ordinal_table;      /// Collection of ordinals (indexes into the Address Table).
    NameTable               name_table;         /// Collection of export names.
};

/// \brief  Describes an entry in the Import Lookup Table.
struct PeImportLookupEntry
{
    uint32_t    ord_name_flag : 1;  /// If 1, the entry uses an ordinal number, otherwise an entry from the Hint/Name Table
    union
    {
        uint32_t    ordinal  : 16;  /// The import's ordinal number, if ord_name_flag is 1
        uint32_t    name_rva : 31;  /// The RVA of the entry in the Hint/Name Table if ord_name_flag is 0
    };
    // The above is what's in the file.

    // These are extracted from the Hint/Name table.
    // That table is not loaded separately, its data is stored here.
    uint16_t    hint;   /// Hint value from the Hint/Name Table. Meaningless if ord_name_flag is 1
    std::string name;   /// Name read from the Hint/Name Table.  Meaningless if ord_name_flag is 1
};

/// \brief  Describes an entry in the Import Directory Table.
struct PeImportDirectoryEntry
{
    using LookupTable = std::vector<PeImportLookupEntry>;

    uint32_t    import_lookup_table_rva;    /// RVA of the Import Lookup Table, where function ordinals or names are stored.
    uint32_t    timestamp;                  /// Timestamp value. Always zero in the file, set after the image is loaded and bound.
    uint32_t    forwarder_chain;            /// Index of the first forwarder reference
    uint32_t    name_rva;                   /// RVA of the imported module's name
    uint32_t    import_address_table_rva;   /// RVA of the Import Address Table. Same content as \c import_lookup_table_rva, until the image is loaded and bound.
    // The above is what's in the file.

    std::string module_name;                /// The name of the imported module, extracted via the \c name_rva value.
    LookupTable lookup_table;               /// Table of function names or ordinal numbers imported from this imported module.
};

enum class PeDebugType : uint32_t
{
    Unknown                 =  0,   // Unknown value ignored by all tools
    COFF                    =  1,   // COFF debug information
    CodeView                =  2,   // Visual C++ debug information
    FPO                     =  3,   // Frame Pointer Omission information
    Misc                    =  4,   // Location of the debug file
    Exception               =  5,   // A copy of .pdata section
    Fixup                   =  6,   // Reserved
    OMapToSource            =  7,   // Mapping from an RVA in image to an RVA in source image
    OMapFromSource          =  8,   // Mapping from an RVA in source image to an RVA in image
    Borland                 =  9,   // Reserved for Borland
    Reserved                = 10,   // Reserved
    CLSID                   = 11,   // Reserved
    VC_FEATURE              = 12,   // Visual C++
    POGO                    = 13,
    ILTCG                   = 14,
    MPX                     = 15,
    Repro                   = 16,   // PE determinism or reproducibility
    ExDllCharacteristics    = 20    // Extended DLL characteristics bits
};

/// \brief  Represents a GUID
struct Guid
{
    uint32_t    data1;
    uint16_t    data2;
    uint16_t    data3;
    uint8_t     data4[8];
};

/// \brief  Base of two CodeView information structures.
struct PeDebugCv
{
    uint32_t    cv_signature;
    uint32_t    age;
    std::string pdb_filepath;
};
struct PeDebugCvPDB20 : public PeDebugCv
{
    int32_t     offset;
    uint32_t    signature;
};
struct PeDebugCvPDB70 : public PeDebugCv
{
    Guid        signature;
};

struct PeDebugMisc
{
    uint32_t    data_type;
    uint32_t    length;
    uint8_t     unicode;
    uint8_t     reserved[3];

    std::vector<uint8_t>    data;

    static constexpr uint32_t   DataTypeExeName = 1;
};
/// \brief  Describes an entry the Debug Directory
struct PeDebugDirectoryEntry
{
    uint32_t    characteristics;        // Reserved, must be zero
    uint32_t    timestamp;              // Date and time when the debug data was created
    uint16_t    version_major;          // Major version of debug data format
    uint16_t    version_minor;          // Minor version of debug data format
    uint32_t    type;                   // Format of dedbugging information
    uint32_t    size_of_data;           // Size of debug data, excluding Debug Directory
    uint32_t    address_of_raw_data;    // Address of debug data when loaded
    uint32_t    pointer_to_raw_data;    // File location of raw data
    // The above is what's in the file

    bool                    data_loaded;    // Was the raw data loaded?
    std::vector<uint8_t>    data;           // Any raw data that was loaded

    static constexpr uint32_t  SignaturePDB70{0x53445352};
    static constexpr uint32_t  SignaturePDB20{0x3031424E};

    std::unique_ptr<PeDebugCv> make_cv_struct() const
    {
        constexpr size_t pdb20_size{sizeof(PeDebugCvPDB20::cv_signature) + sizeof(PeDebugCvPDB20::age) + sizeof(PeDebugCvPDB20::offset) + sizeof(PeDebugCvPDB20::signature) + 1};
        if (data_loaded && data.size() >= pdb20_size)
        {
            const auto *p{data.data()};
            uint32_t    sig = *(reinterpret_cast<const uint32_t *>(p));
            p += sizeof(uint32_t);

            if (sig == SignaturePDB70)
            {
                constexpr size_t pdb70_size{sizeof(PeDebugCvPDB70::cv_signature) +
                                            sizeof(PeDebugCvPDB70::age) +
                                            sizeof(PeDebugCvPDB70::signature.data1) +
                                            sizeof(PeDebugCvPDB70::signature.data2) +
                                            sizeof(PeDebugCvPDB70::signature.data3) +
                                            sizeof(PeDebugCvPDB70::signature.data4) +
                                            1};
                if (data.size() >= pdb70_size)
                {
                    auto rv{std::make_unique<PeDebugCvPDB70>()};

                    rv->cv_signature = sig;

                    // read the GUID
                    rv->signature.data1 = *(reinterpret_cast<const uint32_t *>(p));
                    p += sizeof(uint32_t);
                    rv->signature.data2 = *(reinterpret_cast<const uint16_t *>(p));
                    p += sizeof(uint16_t);
                    rv->signature.data3 = *(reinterpret_cast<const uint16_t *>(p));
                    p += sizeof(uint16_t);
                    std::memcpy(rv->signature.data4, p, sizeof(rv->signature.data4));
                    p += sizeof(rv->signature.data4);

                    rv->age = *(reinterpret_cast<const uint32_t *>(p));
                    p += sizeof(uint32_t);

                    rv->pdb_filepath = reinterpret_cast<const char *>(p);
                    return rv;
                }
            }
            else if (sig == SignaturePDB20)
            {
                auto rv{std::make_unique<PeDebugCvPDB20>()};

                rv->cv_signature = sig;

                rv->offset = *(reinterpret_cast<const int32_t *>(p));
                p += sizeof(int32_t);
                rv->signature = *(reinterpret_cast<const uint32_t *>(p));
                p += sizeof(uint32_t);
                rv->age = *(reinterpret_cast<const uint32_t *>(p));
                p += sizeof(uint32_t);

                rv->pdb_filepath = reinterpret_cast<const char *>(p);

                return rv;
            }
        }

        return nullptr;
    }

// The \c make_misc_struct function probably works but it has not been tested
// since I haven't found any PE executables old enough to use the MISC debug
// format. Remove this definition at your own risk.
#define NO_DEBUG_MISC_TYPE
#if !defined(NO_DEBUG_MISC_TYPE)
    std::unique_ptr<PeDebugMisc> make_misc_struct() const
    {
        constexpr size_t misc_size{sizeof(PeDebugMisc::data_type) + sizeof(PeDebugMisc::length) + sizeof(PeDebugMisc::unicode) + sizeof(PeDebugMisc::reserved)};
        if (data_loaded && data.size() >= misc_size)
        {
            auto rv{std::make_unique<PeDebugMisc>()};
            const auto *p{data.data()};

            rv->data_type = *(reinterpret_cast<const uint32_t *>(p));
            p += sizeof(rv->data_type);
            rv->length = *(reinterpret_cast<const uint32_t *>(p));
            p += sizeof(rv->length);
            rv->unicode = *p++;
            std::memcpy(&rv->reserved[0], p, sizeof(rv->reserved));
            p += sizeof(rv->reserved);
            auto start = data.begin() + (data.size() - (p - data.data()));
            rv->data.assign(start, data.end());

            return rv;
        }

        return nullptr;
    }
#endif
};

/// \brief  Contains information about the new PE section of an executable file
class PeExeInfo
{
public:
    // Types
    using DataDirectory     = std::vector<PeDataDirectoryEntry>;
    using SectionTable      = std::vector<PeSection>;
    using ImportDirectory   = std::vector<PeImportDirectoryEntry>;
    using DebugDirectory    = std::vector<PeDebugDirectoryEntry>;


    /// \brief  Construct a \c PeExeInfo object from a stream.
    /// \param stream           An \c std::istream instance from which to read.
    /// \param header_location  Position in the file at which the PE portion begins.
    /// \param options          Flags indicating what parts of an executable file
    ///                         are to be loaded.
    ///
    /// Loading the raw section data can be expensive in terms of time and memory.
    /// If your program requires the raw section data then pass \c true in the
    /// \p load_raw_data parameter.
    PeExeInfo(std::istream &stream, size_t header_location, LoadOptions::Options options);

    /// \brief  Return the file position of the PE header.
    size_t header_position() const noexcept
    {
        return _header_position;
    }

    /// \brief  Return a reference to the PE header.
    ///
    /// This header will be present in all PE executables.
    const PeImageFileHeader &header() const noexcept
    {
        return _image_file_header;
    }

    /// \brief  Return a pointer to the 32-bit optional PE header, if it exists.
    ///
    /// The 32-bit optional header of an executable will only exist if the executable
    /// is a 32-bit PE type, so the returned pointer may be null.
    const PeOptionalHeader32 *optional_header_32() const noexcept
    {
        return _optional_32.get();
    }

    /// \brief  Return a pointer to the 64-bit optional PE header, if it exists.
    ///
    /// The 64-bit optional header of an executable will only exist if the executable
    /// is a 64-bit PE type, so the returned pointer may be null.
    const PeOptionalHeader64 *optional_header_64() const noexcept
    {
        return _optional_64.get();
    }

    /// \brief  Return a reference to the Data Directory
    const DataDirectory &data_directory() const noexcept
    {
        return _data_directory;
    }

    /// \brief  Return a reference to the Section Table
    const SectionTable &sections() const noexcept
    {
        return _sections;
    }

    /// \brief  Return a reference to the Imports Directory
    ///
    /// The Imports data may not exist if the module doesn't import anything,
    /// so the returned pointer may be null.
    const ImportDirectory *imports() const noexcept
    {
        return _imports.get();
    }

    /// \brief  Return \c true if the PE executable has imports, \c false otherwise.
    bool has_imports() const noexcept
    {
        return _imports != nullptr;
    }

    /// \brief  Return a reference to the Exports data
    ///
    /// The Exports data may not exist if the module doesn't export anything,
    /// so the returned pointer may be null.
    const PeExports *exports() const noexcept
    {
        return _exports.get();
    }

    /// \brief  Return \c true if the PE executable has exports, \c false otherwise.
    const bool has_exports() const noexcept
    {
        return _exports != nullptr;
    }

    /// \brief  Return a reference to the Debug Directory
    const DebugDirectory debug_directory() const noexcept
    {
        return _debug_directory;
    }
private:
    size_t                              _header_position;   /// Absolute position in the file of the PE header. useful for offset calculations.
    PeImageFileHeader                   _image_file_header; /// The PE image file header structure for this file.
    std::unique_ptr<PeOptionalHeader32> _optional_32;       /// Pointer to 32-bit Optional Header. Either this or the one below, never both.
    std::unique_ptr<PeOptionalHeader64> _optional_64;       /// Pointer to 64-bit Optional Header. Either this or the one above, never both.
    DataDirectory                       _data_directory;    /// The Data Directory
    SectionTable                        _sections;          /// The Sections info, headers and optionally raw data
    std::unique_ptr<ImportDirectory>    _imports;           /// The Import Directory, including read import module names and function names.
    std::unique_ptr<PeExports>          _exports;           /// The Export tables data
    DebugDirectory                      _debug_directory;   /// The Debug Directory


    void load_image_file_header(std::istream &stream);
    void load_optional_header_base(std::istream &stream, PeOptionalHeaderBase &header);
    void load_optional_header_32(std::istream &stream);
    void load_optional_header_64(std::istream &stream);
    void load_exports(std::istream &stream);
    void load_imports(std::istream &stream, bool using_64);
    void load_debug_directory(std::istream &stream, LoadOptions::Options options);
};

#endif  //_EXELIB_PEEXE_H_
