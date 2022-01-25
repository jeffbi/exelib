/// \file   PEExe.h
/// Classes and structures describing the PE section of a Portable Executable
/// format executable.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_PEEXE_H_
#define _EXELIB_PEEXE_H_

#include <cstdint>
#include <iosfwd>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "LoadOptions.h"
#include "readstream.h"


/// \brief  Represents a GUID
struct Guid
{
    uint32_t    data1;
    uint16_t    data2;
    uint16_t    data3;
    uint8_t     data4[8];
};

/// \brief  Describes the PE-style header
struct PeImageFileHeader
{
    uint32_t	signature;				///< Image file signature: PE\0\0 = 0x00004550
    uint16_t	target_machine;			///< Number that identifies the type of target machine; see #MachineType enum
    uint16_t	num_sections;			///< Number of sections in the Section Table
    uint32_t	timestamp;				///< Unix-style timestamp indicating when the file was created.
    uint32_t	symbol_table_offset;	///< Offset of the Symbol Table; zero indicats no symbol table is present
    uint32_t	num_symbols;			///< Number of entries in the Symbol Table
    uint16_t	optional_header_size;	///< Size of the optional header; will be zero for an object file
    uint16_t	characteristics;		///< Flags indicating the characteristics of the file

    static constexpr uint32_t   pe_signature{0x00004550};

    /// \brief  Enumeration for the characteristics data member.
    enum class Characteristics : uint16_t
    {
        RelocsStripped          = 0x0001,   ///< Image only; WinCE and NT and higher; indicates the file does not contain base relocations and must therefore be loaded at its preferred base address.
        ExecutableImage         = 0x0002,   ///< Image only; indicates the image file is valid and can be run; if not set, indicates a linker error.
        LineNumsStripped        = 0x0004,   ///< COFF line numbers have been removed. This flag is deprecated and should be zero.
        LocalSymsStripped       = 0x0008,   ///< COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
        AggressiveWsTrim        = 0x0010,   ///< Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
        LargeAddressAware       = 0x0020,   ///< Application can handle > 2 GB addresses.
        //                      = 0x0040,   // This flag is reserved for future use.
        BytesReversedLO         = 0x0080,   ///< Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
        Machine32Bit            = 0x0100,   ///< Machine is based on a 32-bit-word architecture.
        DebugStripped           = 0x0200,   ///< Debugging information is removed from the image file.
        RemovableRunFromSwap    = 0x0400,   ///< If the image is on removable media, fully load it and copy it to the swap file.
        NetRunFromSwap          = 0x0800,   ///< If the image is on network media, fully load it and copy it to the swap file.
        System                  = 0x1000,   ///< The image file is a system file, not a user program.
        DLL                     = 0x2000,   ///< The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
        UPSystemOnly	        = 0x4000,   ///< The file should be run only on a uniprocessor machine.
        BytesReversedHI	        = 0x8000    ///< Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    };

    enum class MachineType : uint16_t
    {
        Unknown     = 0x0000,   ///< The contents of this field are assumed to be applicable to any machine type
        AM33        = 0x01D3,   ///< Matsushita AM33
        AMD64       = 0x8664,   ///< x64
        ARM         = 0x01C0,   ///< ARM little endian
        ARM64       = 0xAA64,   ///< ARM64 little endian
        ARMNT       = 0x01C4,   ///< ARM Thumb-2 little endian
        EBC         = 0x0EBC,   ///< EFI byte code
        I386        = 0x014C,   ///< Intel 386 or later processors and compatible processors
        IA64        = 0x0200,   ///< Intel Itanium processor family
        M32R        = 0x9041,   ///< Mitsubishi M32R little endian
        MIPS16      = 0x0266,   ///< MIPS16
        MIPSFPU     = 0x0366,   ///< MIPS with FPU
        MIPSFPU16   = 0x0466,   ///< MIPS16 with FPU
        PowerPC     = 0x01F0,   ///< Power PC little endian
        PowerPCFP   = 0x01F1,   ///< Power PC with floating point support
        R4000       = 0x0166,   ///< MIPS little endian
        RISCV32     = 0x5032,   ///< RISC-V 32-bit address space
        RISCV64     = 0x5064,   ///< RISC-V 64-bit address space
        RISCV128    = 0x5128,   ///< RISC-V 128-bit address space
        SH3         = 0x01A2,   ///< Hitachi SH3
        SH3DSP      = 0x01A3,   ///< Hitachi SH3 DSP
        SH4         = 0x01A6,   ///< Hitachi SH4
        SH5         = 0x01A8,   ///< Hitachi SH5
        Thumb       = 0x01C2,   ///< Thumb
        WCEMIPSv2   = 0x0169    ///< MIPS little-endian WCE v2
    };
};

/// \brief  Base class for the PE "Optional" headers.
///
/// The PeOptionalHeader32 and PeOptionalHeader64 structures differ slightly
/// but both begin with the members in this structure.
/// The differences are that the \c base_of_data member does not exist in the 64-bit header,
/// and several of the members are different sizes.
struct PeOptionalHeaderBase
{
    uint16_t magic;                     ///< Magic number that identifies the type of the image file. 0x010B - PE32 (32 bit), 0x0107 - ROM image, 0x020B - PE32+ (64 bit)
    uint8_t  linker_version_major;      ///< Linker major version number
    uint8_t  linker_version_minor;      ///< Linker minor version number
    uint32_t code_size;                 ///< The size of the code (text) section, or the sum of all code sections if there are multiple code sections
    uint32_t initialized_data_size;     ///< The size of the initialized data section, or the sum of all sections if there are multiple sections
    uint32_t uninitialized_data_size;   ///< The size of the uninitialized (BSS) data section, or the sum of all sections if there are multiple sections
    uint32_t address_of_entry_point;    ///< The address of the entry point relative to the image base when executable file is loaded into memory. Zero if there is no entry point.
    uint32_t base_of_code;              ///< The address relative to the image base of the beginning-of-code section when it is loaded into memory.
};

/// \brief  Describes the 32-bit image optional header.
struct PeOptionalHeader32 : public PeOptionalHeaderBase
{
    uint32_t base_of_data;              ///< The address relative to the image base of the beginning-of-data section when it is loaded into memory. Note that this member does not exist for PE32+ (64-bit) image files.
    uint32_t image_base;                ///< The preferred address of the first byte of image when loaded into memory.
    uint32_t section_alignment;         ///< The alignment (in bytes) of sections when they are loaded into memory.
    uint32_t file_alignment;            ///< The alignment factor (in bytes) that is used to align the raw data of sections in the image file.
    uint16_t os_version_major;          ///< The major version number of the required operating system.
    uint16_t os_version_minor;          ///< The minor version number of the required operating system.
    uint16_t image_version_major;       ///< The major version number of the image.
    uint16_t image_version_minor;       ///< The minor version number of the image.
    uint16_t subsystem_version_major;   ///< The major version number of the subsystem.
    uint16_t subsystem_version_minor;   ///< The minor version number of the subsystem.
    uint32_t win32_version_value;       ///< Reserved. Must be zero.
    uint32_t size_of_image;             ///< The size (in bytes) of the image, including all headers, as the image is loaded in memory.
    uint32_t size_of_headers;           ///< The combined size of an MS-DOS stub, PE header, and section headers.
    uint32_t checksum;                  ///< The image file checksum.
    uint16_t subsystem;                 ///< The subsystem that is required to run this image. See the #PeSubsystem enum.
    uint16_t dll_characteristics;       ///< A bitmap describing the image characteristics. See the #PeDllCharacteristics enum.
    uint32_t size_of_stack_reserve;     ///< The size of the stack to reserve.
    uint32_t size_of_stack_commit;      ///< The size of the stack to commit.
    uint32_t size_of_heap_reserve;      ///< The size of the local heap space to reserve.
    uint32_t size_of_heap_commit;       ///< The size of the local heap space to commit.
    uint32_t loader_flags;              ///< Reserved, must be zero.
    uint32_t num_rva_and_sizes;         ///< The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
};

/// \brief  Describes the 64-bit image optional header.
///         Note that the \c base_of_data member does not exist in the structure.
struct PeOptionalHeader64 : public PeOptionalHeaderBase
{
    uint64_t image_base;                ///< The preferred address of the first byte of image when loaded into memory.
    uint32_t section_alignment;         ///< The alignment (in bytes) of sections when they are loaded into memory.
    uint32_t file_alignment;            ///< The alignment factor (in bytes) that is used to align the raw data of sections in the image file.
    uint16_t os_version_major;          ///< The major version number of the required operating system.
    uint16_t os_version_minor;          ///< The minor version number of the required operating system.
    uint16_t image_version_major;       ///< The major version number of the image.
    uint16_t image_version_minor;       ///< The minor version number of the image.
    uint16_t subsystem_version_major;   ///< The major version number of the subsystem.
    uint16_t subsystem_version_minor;   ///< The minor version number of the subsystem.
    uint32_t win32_version_value;       ///< Reserved. Must be zero.
    uint32_t size_of_image;             ///< The size (in bytes) of the image, including all headers, as the image is loaded in memory.
    uint32_t size_of_headers;           ///< The combined size of an MS-DOS stub, PE header, and section headers.
    uint32_t checksum;                  ///< The image file checksum.
    uint16_t subsystem;                 ///< The subsystem that is required to run this image. See the #PeSubsystem enum.
    uint16_t dll_characteristics;       ///< A bitmap describing the image characteristics. See the #PeDllCharacteristics enum.
    uint64_t size_of_stack_reserve;     ///< The size of the stack to reserve.
    uint64_t size_of_stack_commit;      ///< The size of the stack to commit.
    uint64_t size_of_heap_reserve;      ///< The size of the local heap space to reserve.
    uint64_t size_of_heap_commit;       ///< The size of the local heap space to commit.
    uint32_t loader_flags;              ///< Reserved, must be zero.
    uint32_t num_rva_and_sizes;         ///< The number of data-directory entries in the remainder of the optional header. Each describes a location and size.
};


/// \brief  Enumeration of the Subsystems for the values of the PeOptionalHeader32::subsystem and PeOptionalHeader64::subsystem structure members.
enum class PeSubsystem : uint16_t
{
    Unknown                 = 0,    ///< An unknown subsystem
    Native                  = 1,    ///< Device drivers and native Windows processes
    Windows_GUI             = 2,    ///< The Windows graphical user interface (GUI) subsystem
    Windows_CUI             = 3,    ///< The Windows character subsystem
    OS2_CUI                 = 5,    ///< The OS/2 character subsystem
    Posix_CUI               = 7,    ///< The Posix character subsystem
    NativeWindows           = 8,    ///< Native Win9x driver
    WindowsCE_GUI           = 9,    ///< Windows CE
    EfiApplication          = 10,   ///< An Extensible Firmware Interface (EFI) application
    EfiBootServiceDriver    = 11,   ///< An EFI driver with boot services
    EfiRuntimeDriver        = 12,   ///< An EFI driver with run-time services
    EfiROM                  = 13,   ///< An EFI ROM image
    XBox                    = 14,   ///< Xbox
    WindowsBootApplication  = 16,   ///< Windows boot application
    XBoxCodeCatalog         = 17    ///< Xbox code catalog
};

/// \brief  Enumeration of the DLL characteristics for the values of the PeOptionalHeader32::dll_characteristics and PeOptionalHeader64::dll_characteristics structure members.
enum class PeDllCharacteristics : uint16_t
{
    HighEntropyVA       = 0x0020,   ///< Image can handle a high entropy 64-bit virtual address space
    DynamicBase         = 0x0040,   ///< DLL can be relocated at load time
    ForceIntegrity      = 0x0080,   ///< Code Integrity checks are enforced
    NxCompatible        = 0x0100,   ///< Image is NX compatible
    NoIsolation         = 0x0200,   ///< Isolation aware, but do not isolate the image
    NoSEH               = 0x0400,   ///< Does not use structured exception handling
    NoBind              = 0x0800,   ///< Do not bind the image
    AppContainer        = 0x1000,   ///< Image must execute in an AppContainer
    WmdDriver           = 0x2000,   ///< A WMD driver
    ControlFlowGuard    = 0x4000,   ///< Image supports Control Flow Guard
    TerminalServerAware = 0x8000    ///< Terminal server aware
};

/// \brief  Describes an entry in the Data Directory.
///         This structure is used in several places in a PE executable file.
struct PeDataDirectoryEntry
{
    uint32_t    virtual_address;    ///< RVA of the table.
    uint32_t    size;               ///< Size in bytes of the table.
};

/// \brief  Read a #PeDataDirectory structure from an input stream.
inline void read_data_directory_entry(std::istream &stream, PeDataDirectoryEntry &entry)
{
    read(stream, entry.virtual_address);
    read(stream, entry.size);
}


/// \brief  Describes a Section header.
///         Each row of the section table is, in effect, a section header.
struct PeSectionHeader
{
    uint8_t     name[8];                ///< An 8-byte, null-padded UTF-8 encoded string. If the string is exactly 8 characters long, there is no terminating null.
    uint32_t    virtual_size;           ///< The total size of the section when loaded into memory.
    uint32_t    virtual_address;        ///< The address of the first byte of the section relative to the image base when the section is loaded into memory.
    uint32_t    size_of_raw_data;       ///< The size of the initialized data on disk.
    uint32_t    raw_data_position;      ///< The file pointer to the first page of the section within the file.
    uint32_t    relocations_position;   ///< The file pointer to the beginning of relocation entries for the section. This is set to zero for executable images or if there are no relocations.
    uint32_t    line_numbers_position;  ///< The file pointer to the beginning of line-number entries for the section.
    uint16_t    number_of_relocations;  ///< The number of relocation entries for the section. This is set to zero for executable images.
    uint16_t    number_of_line_numbers; ///< The number of line-number entries for the section. This value should be zero for an image.
    uint32_t    characteristics;        ///< The flags that describe the characteristics of the section. See the #PeSectionHeaderCharacteristics enum.
};

/// \brief  The flags that describe the characteristics of a Section. Used for the PeSectionHeader::characteristics member.
enum class PeSectionHeaderCharacteristics : uint32_t
{
    //                  = 0x00000000,   // reserved
    //                  = 0x00000001,   // reserved
    //                  = 0x00000002,   // reserved
    //                  = 0x00000004,   // reserved
    NoPadding           = 0x00000008,   ///< Section should not be padded to the next boundary. Object files only. Obsolete.
    //                  = 0x00000010,   // reserved
    ExecutableCode      = 0x00000020,   ///< Section contains executable code.
    InitializedData     = 0x00000040,   ///< Section contains initialized data.
    UninitializedData   = 0x00000080,   ///< Section contains unitialized data.
    LinkOther           = 0x00000100,   ///< reserved
    LinkInfo            = 0x00000200,   ///< Section contains comments or other information. Object files only.
    //                  = 0x00000400,   // reserved
    LinkRemove          = 0x00000800,   ///< Section will not become part of the image. Object files only.
    LinkCOMDAT          = 0x00001000,   ///< Section contains COMDAT data. Object files only.
    GlobalPointerData   = 0x00008000,   ///< Section contains data referenced through the Global Pointer
    MemPurgable         = 0x00020000,   ///< reserved
    Mem16Bit            = 0x00020000,   ///< reserved
    MemLocked           = 0x00040000,   ///< reserved
    MemPreload          = 0x00080000,   ///< reserved
    Align1Bytes         = 0x00100000,   ///< Align data on a 1-byte boundary. Object files only.
    Align2Bytes         = 0x00200000,   ///< Align data on a 2-byte boundary. Object files only.
    Align4Bytes         = 0x00300000,   ///< Align data on a 4-byte boundary. Object files only.
    Align8Bytes         = 0x00400000,   ///< Align data on a 8-byte boundary. Object files only.
    Align16Bytes        = 0x00500000,   ///< Align data on a 16-byte boundary. Object files only.
    Align32Bytes        = 0x00600000,   ///< Align data on a 32-byte boundary. Object files only.
    Align64Bytes        = 0x00700000,   ///< Align data on a 64-byte boundary. Object files only.
    Align128Bytes       = 0x00800000,   ///< Align data on a 128-byte boundary. Object files only.
    Align256Bytes       = 0x00900000,   ///< Align data on a 256-byte boundary. Object files only.
    Align512Bytes       = 0x00A00000,   ///< Align data on a 512-byte boundary. Object files only.
    Align1024Bytes      = 0x00B00000,   ///< Align data on a 1024-byte boundary. Object files only.
    Align2048Bytes      = 0x00C00000,   ///< Align data on a 2048-byte boundary. Object files only.
    Align4096Bytes      = 0x00D00000,   ///< Align data on a 4096-byte boundary. Object files only.
    Align8192Bytes      = 0x00E00000,   ///< Align data on a 8192-byte boundary. Object files only.
    AlignMask           = 0x00F00000,   ///< Bit mask encompassing the Alignment values.
    LinkNRelocOverflow  = 0x01000000,   ///< Section contains extended relocations
    MemDiscardable      = 0x02000000,   ///< Section can be discarded
    MemNotCached        = 0x04000000,   ///< Section cannot be cached
    MemNotPaged         = 0x08000000,   ///< Section is not pageable
    MemShared           = 0x10000000,   ///< Section can be shared in memory
    MemExecute          = 0x20000000,   ///< Section can be executed as code
    MemRead             = 0x40000000,   ///< Section can be read
    MemWrite            = 0x80000000    ///< Section can be written to
};

/// \brief  Represents a Section in a PE image file.
///         A Section is comprised of a Section header followed by the raw bytes making up the section.
class PeSection
{
public:
    /// \brief  Construct a PeSection object from a #PeSectionHeader and a \c vector of raw data.
    ///         The raw data is moved into the new object.
    PeSection(const PeSectionHeader &header, std::vector<uint8_t> &&data)
        : _header{header}
        , _data{std::move(data)}
        , _data_loaded{true}
    {}

    /// \brief  Construct a PeSection object from a #PeSectionHeader and a \c vector of raw data.
    ///         The raw data is copied into the new object.
    PeSection(const PeSectionHeader &header, const std::vector<uint8_t> &data)
        : _header{header}
        , _data{data}
        , _data_loaded{true}
    {}

    /// \brief  Construct a PeSection object from a #PeSectionHeader. No raw data is loaded.
    PeSection(const PeSectionHeader &header)
        :_header{header}
        , _data_loaded{false}
    {}

    /// \brief  The default constructor is deleted.
    PeSection() = delete;
    /// \brief  The copy constructor.
    PeSection(const PeSection &other) = default;
    /// \brief  The move constructor.
    PeSection(PeSection &&other) = default;
    /// \brief  The assignment operator.
    PeSection &operator=(const PeSection &other) = default;
    /// \brief  The move assignment operator.
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
    ///         smaller of #virtual_size() or #raw_data_size().
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
    uint32_t    export_flags;               ///< Reserved, must be zero.
    uint32_t    timestamp;                  ///< Date and time the export data was created.
    uint16_t    version_major;              ///< Major version number.
    uint16_t    version_minor;              ///< Minor version number.
    uint32_t    name_rva;                   ///< RVA of the ASCII string containing the name of the DLL.
    uint32_t    ordinal_base;               ///< Starting ordinal number for exports in this image. Usually set to 1.
    uint32_t    num_address_table_entries;  ///< Number of entries in the Export Address Table.
    uint32_t    num_name_pointers;          ///< Number of entries in the Name Pointer Table, and in the ordinals table.
    uint32_t    export_address_rva;         ///< RVA of the Export Address Table.
    uint32_t    name_pointer_rva;           ///< RVA of the Export Name Pointer Table.
    uint32_t    ordinal_table_rva;          ///< RVA of the Export Ordinal Table.
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

/// \brief  Describes the Exports section
struct PeExports
{
    using AddressTable      = std::vector<PeExportAddressTableEntry>;
    using NamePointerTable  = std::vector<uint32_t>;
    using OrdinalTable      = std::vector<uint16_t>;
    using NameTable         = std::vector<std::string>;

    PeExportDirectory       directory;          ///< Exports info including addresses of tables
    std::string             name;               ///< Name of the DLL, extracted via \c directory.name_rva.
    AddressTable            address_table;      ///< Collection of Address Table entries.

#if !defined(EXELIB_NO_LOAD_FORWARDERS)
    std::vector<uint32_t>   forward_indices;    /// Collection of indexes into the Address Table for forwarders
#endif
        //TODO: consider merging the next
        //      three items into a single
        //      collection!!!
    NamePointerTable        name_pointer_table; ///< Collection of RVAs into the Export Name Table
    OrdinalTable            ordinal_table;      ///< Collection of ordinals (indexes into the Address Table).
    NameTable               name_table;         ///< Collection of export names.
};

/// \brief  Describes an entry in the Import Lookup Table.
struct PeImportLookupEntry
{
    uint32_t    ord_name_flag : 1;  ///< If 1, the entry uses an ordinal number, otherwise an entry from the Hint/Name Table
    union
    {
        uint32_t    ordinal  : 16;  ///< The import's ordinal number, if ord_name_flag is 1
        uint32_t    name_rva : 31;  ///< The RVA of the entry in the Hint/Name Table if ord_name_flag is 0
    };
    // The above is what's in the file.

    // These are extracted from the Hint/Name table.
    // That table is not loaded separately, its data is stored here.
    uint16_t    hint;   ///< Hint value from the Hint/Name Table. Meaningless if ord_name_flag is 1
    std::string name;   ///< Name read from the Hint/Name Table.  Meaningless if ord_name_flag is 1
};

/// \brief  Describes an entry in the Import Directory Table.
struct PeImportDirectoryEntry
{
    using LookupTable = std::vector<PeImportLookupEntry>;

    uint32_t    import_lookup_table_rva;    ///< RVA of the Import Lookup Table, where function ordinals or names are stored.
    uint32_t    timestamp;                  ///< Timestamp value. Always zero in the file, set after the image is loaded and bound.
    uint32_t    forwarder_chain;            ///< Index of the first forwarder reference
    uint32_t    name_rva;                   ///< RVA of the imported module's name
    uint32_t    import_address_table_rva;   ///< RVA of the Import Address Table. Same content as \c import_lookup_table_rva, until the image is loaded and bound.
    // The above is what's in the file.

    std::string module_name;                ///< The name of the imported module, extracted via the \c name_rva value.
    LookupTable lookup_table;               ///< Table of function names or ordinal numbers imported from this imported module.
};

enum class PeDebugType : uint32_t
{
    Unknown                 =  0,   ///< Unknown value ignored by all tools
    COFF                    =  1,   ///< COFF debug information
    CodeView                =  2,   ///< Visual C++ debug information
    FPO                     =  3,   ///< Frame Pointer Omission information
    Misc                    =  4,   ///< Location of the debug file
    Exception               =  5,   ///< A copy of .pdata section
    Fixup                   =  6,   ///< Reserved
    OMapToSource            =  7,   ///< Mapping from an RVA in image to an RVA in source image
    OMapFromSource          =  8,   ///< Mapping from an RVA in source image to an RVA in image
    Borland                 =  9,   ///< Reserved for Borland
    Reserved                = 10,   ///< Reserved
    CLSID                   = 11,   ///< Reserved
    VC_Feature              = 12,   ///< Visual C++
    POGO                    = 13,
    ILTCG                   = 14,   ///< Link-Time Code Generation
    MPX                     = 15,
    Repro                   = 16,   ///< PE determinism or reproducibility
    ExDllCharacteristics    = 20    ///< Extended DLL characteristics bits
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

/// \brief  Describes a VC_FEATURE debug record
struct PeDebugVcFeature
{
    uint32_t    pre_vc11;
    uint32_t    cpp;
    uint32_t    gs;
    uint32_t    sdl;
    uint32_t    guard_n;
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

// The make_misc_struct function probably works but it has not been tested
// since I haven't found any PE executables old enough to use the MISC debug
// format. Remove this definition at your own risk.
#define EXELIB_NO_DEBUG_MISC_TYPE
#if !defined(EXELIB_NO_DEBUG_MISC_TYPE)
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

    std::unique_ptr<PeDebugVcFeature> make_vc_feature_struct() const
    {
        if (data_loaded && data.size() >= sizeof(uint32_t) * 5)
        {
            auto rv{std::make_unique<PeDebugVcFeature>()};
            const auto *p{data.data()};

            rv->pre_vc11= *(reinterpret_cast<const uint32_t *>(p));
            p += sizeof(rv->pre_vc11);
            rv->cpp = *(reinterpret_cast<const uint32_t *>(p));
            p += sizeof(rv->cpp);
            rv->gs = *(reinterpret_cast<const uint32_t *>(p));
            p += sizeof(rv->gs);
            rv->sdl = *(reinterpret_cast<const uint32_t *>(p));
            p += sizeof(rv->sdl);
            rv->guard_n = *(reinterpret_cast<const uint32_t *>(p));

            return rv;
        }

        return nullptr;
    }
};

/// \brief  Represents a Resource Directory Entry
struct PeResourceDirectoryEntry
{
    uint32_t    name_offset_or_int_id;  ///< Name offset or int ID, depending on the level of the table
    uint32_t    offset;                 ///< If high bit set, offset of data entry, otherwise address of next Resource Directory Table
};

/// \brief  Represents a Resource Directory Table
struct PeResourceDirectory
{
    uint32_t    characteristics;
    uint32_t    timestamp;
    uint16_t    version_major;
    uint16_t    version_minor;
    uint16_t    num_name_entries;
    uint16_t    num_id_entries;

    using ResourceEntries = std::vector<std::unique_ptr<PeResourceDirectoryEntry>>;

    size_t          level;
    ResourceEntries entries;
};


//////////////////////////////////
// Begin CLI metadata definitions
//////////////////////////////////

enum PeCliEntryPointFlags : uint32_t
{
    IlOnly              = 0x00000001,
    Required32Bit       = 0x00000002,
    IlLibrary           = 0x00000004,
    StrongNameSigned    = 0x00000008,
    NativeEntryPoint    = 0x00000010,
    TrackDebugData      = 0x00010000,
    Preferred32Bit      = 0x00020000
};

struct PeCliHeader
{
    uint32_t                size;
    uint16_t                major_runtime_version;
    uint16_t                minor_runtime_version;

    PeDataDirectoryEntry    metadata;
    uint32_t                flags;

    // If NativeEntryPoint is not set, entry_point_token represents a managed entrypoint.
    // If NativeEntryPoint is set, entry_point_RVA represents an RVA to a native entrypoint.
    union
    {
        uint32_t            entry_point_token;
        uint32_t            entry_point_RVA;
    };

    PeDataDirectoryEntry    resources;
    PeDataDirectoryEntry    strong_name_signature;

    PeDataDirectoryEntry    code_manager_table;
    PeDataDirectoryEntry    vtable_fixups;
    PeDataDirectoryEntry    export_address_table_jumps;

    PeDataDirectoryEntry    managed_native_header;
};

struct PeCliStreamHeader
{
    uint32_t    offset;
    uint32_t    size;
    std::string name;
};

struct PeCliMetadataHeader
{
    uint32_t    signature;
    uint16_t    major_version;
    uint16_t    minor_version;
    uint32_t    reserved;
    std::string version;
    uint16_t    flags;
    uint16_t    stream_count;
};

enum class PeCliMetadataTableId
{
    Assembly                = 0x20,
    AssemblyOS              = 0x22,
    AssemblyProcessor       = 0x21,
    AssemblyRef             = 0x23,
    AssemblyRefOS           = 0x25,
    AssemblyRefProcessor    = 0x24,
    ClassLayout             = 0x0F,
    Constant                = 0x0B,
    CustomAttribute         = 0x0C,
    DeclSecurity            = 0x0E,
    EventMap                = 0x12,
    Event                   = 0x14,
    ExportedType            = 0x27,
    Field                   = 0x04,
    FieldLayout             = 0x10,
    FieldMarshal            = 0x0D,
    FieldRVA                = 0x1D,
    File                    = 0x26,
    GenericParam            = 0x2A,
    GenericParamConstraint  = 0x2C,
    ImplMap                 = 0x1C,
    InterfaceImpl           = 0x09,
    ManifestResource        = 0x28,
    MemberRef               = 0x0A,
    MethodDef               = 0x06,
    MethodImpl              = 0x19,
    MethodSemantics         = 0x18,
    MethodSpec              = 0x2B,
    Module                  = 0x00,
    ModuleRef               = 0x1A,
    NestedClass             = 0x29,
    Param                   = 0x08,
    Property                = 0x17,
    PropertyMap             = 0x15,
    StandAloneSig           = 0x11,
    TypeDef                 = 0x02,
    TypeRef                 = 0x01,
    TypeSpec                = 0x1B
};

/// \brief  Defines the basic structure of the #~ stream.
struct PeCliMetadataTablesStreamHeader
{
    uint32_t                reserved0;
    uint8_t                 major_version;
    uint8_t                 minor_version;
    uint8_t                 heap_sizes;
    uint8_t                 reserved1;
    uint64_t                valid_tables;
    uint64_t                sorted_tables;
    std::vector<uint32_t>   row_counts;
    // Following this is an array of tables.
};

//
// The following structures define the rows in the various metadata tables contained in the #~ stream.
//

// Row of Assembly table (0x20)
struct PeCliMetadataRowAssembly
{
    uint32_t    hash_alg_id;
    uint16_t    major_version;
    uint16_t    minor_version;
    uint16_t    build_number;
    uint16_t    revision_number;
    uint32_t    flags;
    uint32_t    public_key;     // index into #Blob heap
    uint32_t    name;           // index into #Strings heap
    uint32_t    culture;        // index into #Strings heap
};

// Row of AssemblyOS table (0x22)
struct PeCliMetadataRowAssemblyOS
{
    uint32_t    os_platformID;
    uint32_t    os_major_version;
    uint32_t    os_minor_version;
};

// Row of AssemblyProcessor table (0x21)
struct PeCliMetadataRowAssemblyProcessor
{
    uint32_t    processor;
};

// Row of AssemblyRef table (x023)
struct PeCliMetadataRowAssemblyRef
{
    uint16_t    major_version;
    uint16_t    minor_version;
    uint16_t    build_number;
    uint16_t    revision_number;
    uint32_t    flags;
    uint32_t    public_key_or_token;    // index into #Blob heap
    uint32_t    name;                   // index into #Strings heap
    uint32_t    culture;                // index into #Strings heap
    uint32_t    hash_value;             // index into #Blob heap
};

// Row of AssemblyRefOS table (x025)
struct PeCliMetadataRowAssemblyRefOS
{
    uint32_t    os_platformID;
    uint32_t    os_major_version;
    uint32_t    os_minor_version;
    uint32_t    assembly_ref;       // index into AssemblyRef table
};

// Row of AssemblyRefProcessor table (x024)
struct PeCliMetadataRowAssemblyRefProcessor
{
    uint32_t    processor;
    uint32_t    assembly_ref;       // index into AssemblyRef table
};

// Row of ClassLayout table (0x0F)
struct PeCliMetadataRowClassLayout
{
    uint16_t    packing_size;
    uint32_t    class_size;
    uint32_t    parent;         // index into TypeDef table
};

// Row of Constant table (0x0B)
struct PeCliMetadataRowConstant
{
    uint8_t     type;
    uint8_t     padding;
    uint32_t    parent;     // index into Param, Field, or Property table
    uint32_t    value;      // index into #Blob heap
};

// Row of CustomAttribute table (0x0C)
struct PeCliMetadataRowCustomAttribute
{
    uint32_t    parent;     // index into a metadata table that has an associated HasCustomAttribute coded index
    uint32_t    type;       // index into the MethodDef or MemberRef table
    uint32_t    value;      // index into #Blob heap
};
//TODO: There is more to this than just this struct. ECMA-335, section II.22.10 describes data in the #Blob heap

// Row of DeclSecurity table (0x0E)
struct PeCliMetadataRowDeclSecurity
{
    uint16_t    action;
    uint32_t    parent;         // index into the TypeDef, MethodDef, or Assembly table
    uint32_t    permission_set; // index into the Blob heap
};

// Row of EventMap table (0x12)
struct PeCliMetadataRowEventMap
{
    uint32_t    parent;     // index into the TypeDef table
    uint32_t    event_list; // index into the Event table
};

// Row of Event table (0x14)
struct PeCliMetadataRowEvent
{
    uint16_t    event_flags;
    uint32_t    name;           // index into the #Strings heap
    uint32_t    event_type;     // index into a TypeDef, a TypeRef, or TypeSpec table
};

// Row of ExportedType table (0x27)
struct PeCliMetadataRowExportedType
{
    uint32_t    flags;
    uint32_t    typedef_id;     // index into a TypeDef table of another module in this Assembly
    uint32_t    type_name;      // index into the #Strings heap
    uint32_t    type_namespace; // index into the #Strings heap
    uint32_t    implementation; // index into either the File table, ExportedType table, or AssemblyRef table
};

// Row of Field table (0x04)
struct PeCliMetadataRowField
{
    uint16_t    flags;
    uint32_t    name;       // index into the #Strings heap
    uint32_t    signature;  // index into the #Blob heap
};

// Row of FieldLayout table (0x10)
struct PeCliMetadataRowFieldLayout
{
    uint32_t    offset;
    uint32_t    field;      // index into the Field table
};

// Row of FieldMarshal table (0x0D)
struct PeCliMetadataRowFieldMarshal
{
    uint32_t    parent;         // index into Field or Param table
    uint32_t    native_type;    // index into the #Blob heap
};

// Row of FieldRVA table (0x1D)
struct PeCliMetadataRowFieldRVA
{
    uint32_t    rva;
    uint32_t    field;  // index into the Field table
};

// Row of File table (0x26)
struct PeCliMetadataRowFile
{
    uint32_t    flags;
    uint32_t    name;       // index into the #Strings heap
    uint32_t    hash_value; // index into the #Blob heap
};

// Row of GenericParam table (0x2A)
struct PeCliMetadataRowGenericParam
{
    uint16_t    number;
    uint16_t    flags;
    uint32_t    owner;  // index into the TypeDef or MethodDef table, specifying the Type or Method to which this generic parameter applies
    uint32_t    name;   // index into the #Strings heap
};

// Row of GenericParamConstraint table (0x2C)
struct PeCliMetadataRowGenericParamConstraint
{
    uint32_t    owner;      // index into the GenericParam table, specifying to which generic parameter this row refers
    uint32_t    constraint; // index into the TypeDef, TypeRef, or TypeSpec tables, specifying from which class this generic parameter is constrained to derive; or which interface this generic parameter is constrained to implement
};

// Row of ImplMap table (0x1C)
struct PeCliMetadataRowImplMap
{
    uint16_t    mapping_flags;
    uint32_t    member_forwarded;   // index into the Field or MethodDef table, however it only ever indexes the MethodDef table, since Field export is not supported
    uint32_t    import_name;        // index into the #Strings heap
    uint32_t    import_scope;       // index into the ModuleRef table
};

// Row of InterfaceImpl table (0x09)
struct PeCliMetadataRowInterfaceImpl
{
    uint32_t    class_;     // ("class", actually, but that's a reserved word) index into the TypeDef table
    uint32_t    interface;  // index into the TypeDef, TypeRef, or TypeSpec table
};

// Row of ManifestResource table (0x28)
struct PeCliMetadataRowManifestResource
{
    uint32_t    offset;
    uint32_t    flags;
    uint32_t    name;           // index into the #Strings heap
    uint32_t    implementation; // index into a File table, a AssemblyRef table, or null
};

// Row of MemberRef table (0x0A)
struct PeCliMetadataRowMemberRef
{
    uint32_t    class_;     // ("class", actually, but that's a reserved word) index into the MethodDef, ModuleRef,TypeDef, TypeRef, or TypeSpec tables
    uint32_t    name;       // index into the #Strings heap
    uint32_t    signature;  // index into the #Blob heap
};

// Row of MethodDef table (0x06)
struct PeCliMetadataRowMethodDef
{
    uint32_t    rva;
    uint16_t    impl_flags;
    uint16_t    flags;
    uint32_t    name;       // index into the #Strings heap
    uint32_t    signature;  // index into the #Blob heap
    uint32_t    param_list; // index into the Param table
};

// Row of MethodImpl table (0x19)
struct PeCliMetadataRowMethodImpl
{
    uint32_t    class_;             // ("class", actually, but that's a reserved word) index into the TypeDef table
    uint32_t    method_body;        // index into the MethodDef or MemberRef table
    uint32_t    method_declaration; // index into the MethodDef or MemberRef table
};

// Row of MethodSemantics table (0x18)
struct PeCliMetadataRowMethodSemantics
{
    uint16_t    semantics;
    uint32_t    method;         // index into the MethodDef
    uint32_t    association;    // index into the Event or Property table
};

// Row of MethodSpec table (0x2B)
struct PeCliMetadataRowMethodSpec
{
    uint32_t    method;         // index into the MethodDef or MemberRef table
    uint32_t    instantiation;  // index into the #Blob heap, holding the signature of this instantiation
};

// Row of Module table (0x00)
struct PeCliMetadataRowModule
{
    uint16_t    generation;     // reserved, must be zero
    uint32_t    name;           // index into the #Strings heap
    uint32_t    mv_id;          // index into the Guid heap; simply a Guid used to distinguish between two versions of the same module
    uint32_t    enc_id;         // index into the Guid heap; reserved, must be zero
    uint32_t    enc_base_id;    // index into the Guid heap; reserved, must be zero
};

// Row of ModuleRef table (0x1A)
struct PeCliMetadataRowModuleRef
{
    uint32_t    name;   // index into the #Strings table
};

// Row of NestedClass table (0x29)
struct PeCliMetadataRowNestedClass
{
    uint32_t    nested_class;       // index into the TypeDef table
    uint32_t    enclosing_class;    // index into the TypeDef table
};

// Row of Param table (0x08)
struct PeCliMetadataRowParam
{
    uint16_t    flags;
    uint16_t    sequence;
    uint32_t    name;       // index into the #Strings heap
};

// Row of Property table (0x17)
struct PeCliMetadataRowProperty
{
    uint16_t    flags;
    uint32_t    name;   // index into the #Strings heap
    uint32_t    type;   // index into the #Blob heap
};

// Row of PropertyMap table (0x15)
struct PeCliMetadataRowPropertyMap
{
    uint32_t    parent;         // index into the TypeDef table
    uint32_t    property_list;  // index into the Property table
};

// Row of StandAloneSig table (0x11)
struct PeCliMetadataRowStandAloneSig
{
    uint32_t    signature;  // index into the #Blob heap
};

// Row of TypeDef table (0x02)
struct PeCliMetadataRowTypeDef
{
    uint32_t    flags;
    uint32_t    type_name;      // index into the #Strings heap
    uint32_t    type_namespace; // index into the #Strings heap
    uint32_t    extends;        // index into the TypeDef, TypeRef, or TypeSpec table
    uint32_t    field_list;     // index into the Field table
    uint32_t    method_list;    // index into the MethodDef table
};

// Row of TypeRef table (0x01)
struct PeCliMetadataRowTypeRef
{
    uint32_t    resolution_scope;   // index into a Module, ModuleRef, AssemblyRef or TypeRef table, or null
    uint32_t    type_name;          // index into the #Strings heap
    uint32_t    type_namespace;     // index into the #Strings heap
};

// Row of TypeSpec table (0x1B)
struct PeCliMetadataRowTypeSpec
{
    uint32_t    signature;  // index into the #Blob heap
};

///////////////////////////////////////
// End of metadata table row structures
///////////////////////////////////////


/// \brief Deconstruction of the #~ stream
class PeCliMetadataTables
{
public:
    void load(BytesReader &reader);

private:
    size_t read_index(BytesReader &reader, uint32_t &ndx, bool wide)
    {
        if (wide)
        {
            reader.read(ndx);
            return sizeof(ndx);
        }
        else
        {
            uint16_t    tmp;

            reader.read(tmp);
            ndx = tmp;
            return sizeof(tmp);
        }
    }
    size_t read_strings_heap_index(BytesReader &reader, uint32_t &ndx)
    {
        return read_index(reader, ndx, _header.heap_sizes & 0x01);
    }
    size_t read_guid_heap_index(BytesReader &reader, uint32_t &ndx)
    {
        return read_index(reader, ndx, _header.heap_sizes & 0x02);
    }
    size_t read_blob_heap_index(BytesReader &reader, uint32_t &ndx)
    {
        return read_index(reader, ndx, _header.heap_sizes & 0x04);
    }
    // ECMA spec does not specify information about the width of indexes into the #US heap.
    // It appears that none of the metadata tables contain indexes into the #US heap,
    // so there is no read_us_heap_index function.

    PeCliMetadataTablesStreamHeader     _header;
    std::vector<PeCliMetadataTableId>   _valid_table_types;

    // A std::unique_ptr for each table type. Null pointers indicate the table does not exist.
    std::unique_ptr<std::vector<PeCliMetadataRowAssembly>>              _assembly_table;
    std::unique_ptr<std::vector<PeCliMetadataRowAssemblyOS>>            _assembly_os_table;
    std::unique_ptr<std::vector<PeCliMetadataRowAssemblyProcessor>>     _assembly_processor;
    std::unique_ptr<std::vector<PeCliMetadataRowAssemblyRef>>           _assembly_ref_table;
    std::unique_ptr<std::vector<PeCliMetadataRowAssemblyRefOS>>         _assembly_ref_os_table;
    std::unique_ptr<std::vector<PeCliMetadataRowAssemblyRefProcessor>>  _assembly_ref_processor_table;
    std::unique_ptr<std::vector<PeCliMetadataRowClassLayout>>           _class_layout_table;
    std::unique_ptr<std::vector<PeCliMetadataRowConstant>>              _constant_table;
    std::unique_ptr<std::vector<PeCliMetadataRowCustomAttribute>>       _custom_attribute_table;
    std::unique_ptr<std::vector<PeCliMetadataRowDeclSecurity>>          _decl_security_table;
    std::unique_ptr<std::vector<PeCliMetadataRowEvent>>                 _event_table;
    std::unique_ptr<std::vector<PeCliMetadataRowEventMap>>              _event_map_table;
    std::unique_ptr<std::vector<PeCliMetadataRowExportedType>>          _exported_type_table;
    std::unique_ptr<std::vector<PeCliMetadataRowField>>                 _field_table;
    std::unique_ptr<std::vector<PeCliMetadataRowFieldLayout>>           _field_layout_table;
    std::unique_ptr<std::vector<PeCliMetadataRowFieldMarshal>>          _field_marshal_table;
    std::unique_ptr<std::vector<PeCliMetadataRowFieldRVA>>              _field_rva_table;
    std::unique_ptr<std::vector<PeCliMetadataRowFile>>                  _file_table;
    std::unique_ptr<std::vector<PeCliMetadataRowGenericParam>>          _generic_param_table;
    std::unique_ptr<std::vector<PeCliMetadataRowGenericParamConstraint>>    _generic_param_constraint_table;
    std::unique_ptr<std::vector<PeCliMetadataRowImplMap>>               _impl_map_table;
    std::unique_ptr<std::vector<PeCliMetadataRowInterfaceImpl>>         _interface_impl_table;
    std::unique_ptr<std::vector<PeCliMetadataRowManifestResource>>      _manifest_resource_table;
    std::unique_ptr<std::vector<PeCliMetadataRowMemberRef>>             _member_ref_table;
    std::unique_ptr<std::vector<PeCliMetadataRowMethodDef>>             _method_def_table;
    std::unique_ptr<std::vector<PeCliMetadataRowMethodImpl>>            _method_impl_table;
    std::unique_ptr<std::vector<PeCliMetadataRowMethodSemantics>>       _method_semantics_table;
    std::unique_ptr<std::vector<PeCliMetadataRowMethodSpec>>            _method_spec_table;
    std::unique_ptr<std::vector<PeCliMetadataRowModule>>                _module_table;
    std::unique_ptr<std::vector<PeCliMetadataRowModuleRef>>             _module_ref_table;
    std::unique_ptr<std::vector<PeCliMetadataRowNestedClass>>           _nested_class_table;
    std::unique_ptr<std::vector<PeCliMetadataRowParam>>                 _param_table;
    std::unique_ptr<std::vector<PeCliMetadataRowProperty>>              _property_table;
    std::unique_ptr<std::vector<PeCliMetadataRowPropertyMap>>           _property_map_table;
    std::unique_ptr<std::vector<PeCliMetadataRowStandAloneSig>>         _stand_alone_sig_table;
    std::unique_ptr<std::vector<PeCliMetadataRowTypeDef>>               _type_def_table;
    std::unique_ptr<std::vector<PeCliMetadataRowTypeRef>>               _type_ref_table;
    std::unique_ptr<std::vector<PeCliMetadataRowTypeSpec>>              _type_spec_table;
};

/// \brief  Specifier for the type of encoded index found in CLI metadata table entries
enum class PeCliEncodedIndexType
{
    TypeDefOrRef,
    HasConstant,
    HasCustomAttribute,
    HasFieldMarshall,
    HasDeclSecurity,
    MemberRefParent,
    HasSemantics,
    MethodDefOrRef,
    MemberForwarded,
    Implementation,
    CustomAttributeType,
    ResolutionScope,
    TypeOrMethodDef
};

/// \brief  Structure returned by the PeCliMetadata::decode_index function.
struct PeCliMetadataTableIndex
{
    PeCliMetadataTableId    table_id;   ///< The identifier of the table to be indexed
    uint32_t                index;      ///< The actual index value
};

/// \brief  Contains the CLI metadata from a managed PE
class PeCliMetadata
{
public:
    PeCliMetadata()
    {}

    void load(std::istream &stream, const std::vector<PeSection> &sections, LoadOptions::Options options);

    const PeCliHeader &cli_header() const noexcept
    {
        return _cli_header;
    }
    const PeCliMetadataHeader *metadata_header() const noexcept
    {
        return _metadata_header.get();
    }
    const std::vector<PeCliStreamHeader> &stream_headers() const noexcept
    {
        return _stream_headers;
    }
    const std::vector<std::vector<uint8_t>> &streams() const noexcept
    {
        return _streams;
    }

    const std::vector<uint8_t> &get_stream(const std::string &stream_name) const
    {
        static const std::vector<uint8_t> empty;

        if (metadata_header())
        {
            for (uint32_t i = 0; i < metadata_header()->stream_count; ++i)
            {
                if (stream_headers()[i].name == stream_name)
                    return streams()[i];
            }
        }

        return empty;
    }

    /// \brief  Return a vector of strings as contained in the CLI \#Strings stream.
    std::vector<std::string> get_strings_heap_strings() const;

    /// \brief  Return a vector of strings as contained in the CLI \#US stream.
    std::vector<std::u16string> get_us_heap_strings() const;

    /// \brief  Return a vector of vectors of byte blobs as contained in the CLI \#Blob stream.
    std::vector<std::vector<uint8_t>> get_blob_heap_blobs() const;

    /// \brief  Return a vector of Guid structures as contained in the CLI \#GUID stream.
    std::vector<Guid> get_guid_heap_guids() const;

    /// \brief  Return a raw pointer to a PeCLiMetadataTables structure containing the parsed CLI \#~ stream.
    const PeCliMetadataTables *metadata_tables() const
    {
        return _tables.get();
    }

    PeCliMetadataTableIndex decode_index(PeCliEncodedIndexType type, uint32_t index) const;

private:
    void load_metadata_tables();

    PeCliHeader                             _cli_header;
    std::unique_ptr<PeCliMetadataHeader>    _metadata_header;
    std::vector<PeCliStreamHeader>          _stream_headers;
    std::vector<std::vector<uint8_t>>       _streams;   // all metadata streams
    std::unique_ptr<PeCliMetadataTables>    _tables;    // from the #~ stream
};

//////////////////////////////////
// End of CLI metadata definitions
//////////////////////////////////



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
    bool has_exports() const noexcept
    {
        return _exports != nullptr;
    }

    /// \brief  Return \c true if the PE executable has CLI metadata, \c false otherwise.
    bool has_cli_metadata() const noexcept
    {
        return _cli_metadata != nullptr;
    }

    /// \brief  Return a reference to the Debug Directory
    const DebugDirectory debug_directory() const noexcept
    {
        return _debug_directory;
    }

private:
    size_t                                  _header_position;   /// Absolute position in the file of the PE header. useful for offset calculations.
    PeImageFileHeader                       _image_file_header; /// The PE image file header structure for this file.
    std::unique_ptr<PeOptionalHeader32>     _optional_32;       /// Pointer to 32-bit Optional Header. Either this or the one below, never both.
    std::unique_ptr<PeOptionalHeader64>     _optional_64;       /// Pointer to 64-bit Optional Header. Either this or the one above, never both.
    DataDirectory                           _data_directory;    /// The Data Directory
    SectionTable                            _sections;          /// The Sections info, headers and optionally raw data
    std::unique_ptr<ImportDirectory>        _imports;           /// The Import Directory, including read import module names and function names.
    std::unique_ptr<PeExports>              _exports;           /// The Export tables data
    DebugDirectory                          _debug_directory;   /// The Debug Directory
    std::unique_ptr<PeCliMetadata>          _cli_metadata;      /// The CLI metadata, if the PE image is managed code


    void load_image_file_header(std::istream &stream);
    void load_optional_header_base(std::istream &stream, PeOptionalHeaderBase &header);
    void load_optional_header_32(std::istream &stream);
    void load_optional_header_64(std::istream &stream);
    void load_exports(std::istream &stream);
    void load_imports(std::istream &stream, bool using_64);
    void load_debug_directory(std::istream &stream, LoadOptions::Options options);
    void load_cli_directory(std::istream &stream, LoadOptions::Options options);
    void load_cli_metadata(std::istream &stream, LoadOptions::Options options);
    void load_resource_info(std::istream &stream, LoadOptions::Options options);
};


inline const PeSection *find_section_by_rva(uint32_t rva, const std::vector<PeSection> &sections)
{
    if (rva > 0)
    {
        for (size_t i = 0; i < sections.size(); ++i)
        {
            if (rva >= sections[i].virtual_address())
            {
                if (i == sections.size() - 1)
                    return &sections[i];    // this is the last one, so it must be it.

                if (rva < sections[i+1].virtual_address())
                    return &sections[i];
            }
        }
    }

    return nullptr;
}

inline size_t get_file_offset(uint32_t rva, const PeSection &section)
{
    return rva - section.virtual_address() + section.header().raw_data_position;
}

#endif  //_EXELIB_PEEXE_H_
