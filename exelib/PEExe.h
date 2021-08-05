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

/// \brief  Describes the PE-style header
struct PeExeHeader
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

    enum MachineType
    {
        UNKNOWN     = 0x0,      // The contents of this field are assumed to be applicable to any machine type
        AM33        = 0x1d3,    // Matsushita AM33
        AMD64       = 0x8664,   // x64
        ARM         = 0x1c0,    // ARM little endian
        ARM64       = 0xaa64,   // ARM64 little endian
        ARMNT       = 0x1c4,    // ARM Thumb-2 little endian
        EBC         = 0xebc,    // EFI byte code
        I386        = 0x14c,    // Intel 386 or later processors and compatible processors
        IA64        = 0x200,    // Intel Itanium processor family
        M32R        = 0x9041,   // Mitsubishi M32R little endian
        MIPS16      = 0x266,    // MIPS16
        MIPSFPU     = 0x366,    // MIPS with FPU
        MIPSFPU16   = 0x466,    // MIPS16 with FPU
        POWERPC     = 0x1f0,    // Power PC little endian
        POWERPCFP   = 0x1f1,    // Power PC with floating point support
        R4000       = 0x166,    // MIPS little endian
        RISCV32     = 0x5032,   // RISC-V 32-bit address space
        RISCV64     = 0x5064,   // RISC-V 64-bit address space
        RISCV128    = 0x5128,   // RISC-V 128-bit address space
        SH3         = 0x1a2,    // Hitachi SH3
        SH3DSP      = 0x1a3,    // Hitachi SH3 DSP
        SH4         = 0x1a6,    // Hitachi SH4
        SH5         = 0x1a8,    // Hitachi SH5
        THUMB       = 0x1c2,    // Thumb
        WCEMIPSV2   = 0x169     // MIPS little-endian WCE v2
    };

    enum Characteristics
    {
        RELOCS_STRIPPED             = 0x0001,   // image only; WinCE and NT and higher; indicates the file does not contain base relocations and must therefore be loaded at its preferred base address.
        EXECUTABLE_IMAGE            = 0x0002,   // image only; indicates the image file is valid and can be run; if not set, indicates a linker error.
        LINE_NUMS_STRIPPED          = 0x0004,   // COFF line numbers have been removed. This flag is deprecated and should be zero.
        LOCAL_SYMS_STRIPPED         = 0x0008,   // COFF symbol table entries for local symbols have been removed. This flag is deprecated and should be zero.
        AGGRESSIVE_WS_TRIM          = 0x0010,   // Obsolete. Aggressively trim working set. This flag is deprecated for Windows 2000 and later and must be zero.
        LARGE_ADDRESS_AWARE         = 0x0020,   // Application can handle > 2 GB addresses.
        //                          = 0x0040,   // This flag is reserved for future use.
        BYTES_REVERSED_LO           = 0x0080,   // Little endian: the least significant bit (LSB) precedes the most significant bit (MSB) in memory. This flag is deprecated and should be zero.
        MACHINE_32BIT               = 0x0100,   // Machine is based on a 32-bit-word architecture.
        DEBUG_STRIPPED              = 0x0200,   // Debugging information is removed from the image file.
        REMOVABLE_RUN_FROM_SWAP     = 0x0400,   // If the image is on removable media, fully load it and copy it to the swap file.
        NET_RUN_FROM_SWAP           = 0x0800,   // If the image is on network media, fully load it and copy it to the swap file.
        SYSTEM                      = 0x1000,   // The image file is a system file, not a user program.
        DLL                         = 0x2000,   // The image file is a dynamic-link library (DLL). Such files are considered executable files for almost all purposes, although they cannot be directly run.
        UP_SYSTEM_ONLY	            = 0x4000,   // The file should be run only on a uniprocessor machine.
        BYTES_REVERSED_HI	        = 0x8000    // Big endian: the MSB precedes the LSB in memory. This flag is deprecated and should be zero.
    };
};

struct Pe32OptionalHeader {
    uint16_t mMagic;                        // 0x010b - PE32, 0x020b - PE32+ (64 bit)
    uint8_t  linker_version_major;
    uint8_t  linker_version_minor;
    uint32_t code_size;
    uint32_t initialized_data_size;
    uint32_t Uninitialized_data_size;
    uint32_t mAddressOfEntryPoint;
    uint32_t mBaseOfCode;
    uint32_t mBaseOfData;
    uint32_t mImageBase;
    uint32_t mSectionAlignment;
    uint32_t mFileAlignment;
    uint16_t mMajorOperatingSystemVersion;
    uint16_t mMinorOperatingSystemVersion;
    uint16_t mMajorImageVersion;
    uint16_t mMinorImageVersion;
    uint16_t mMajorSubsystemVersion;
    uint16_t mMinorSubsystemVersion;
    uint32_t mWin32VersionValue;
    uint32_t mSizeOfImage;
    uint32_t mSizeOfHeaders;
    uint32_t mCheckSum;
    uint16_t mSubsystem;
    uint16_t mDllCharacteristics;
    uint32_t mSizeOfStackReserve;
    uint32_t mSizeOfStackCommit;
    uint32_t mSizeOfHeapReserve;
    uint32_t mSizeOfHeapCommit;
    uint32_t mLoaderFlags;
    uint32_t mNumberOfRvaAndSizes;
};

/// \brief  Contains information about the new PE section of an executable file
class PeExeInfo
{
public:
    /// \brief  Construct a \c PeExeInfo object from a stream.
    /// \param stream           The input stream from which to read.
    /// \param header_location  Position in the file at which the PE portion begins.
    PeExeInfo(std::istream &stream, size_t header_location)
      : _header_position{header_location}
    {
        load_header(stream);

        //TODO: Load more here!!!
    }

    /// \brief  Return the file position of the PE header.
    size_t header_position() const noexcept
    {
        return _header_position;
    }

    /// \brief  Return a reference to the PE header.
    const PeExeHeader &header() const noexcept
    {
        return _pe_header;
    }

private:
    size_t          _header_position;   // absolute position in the file of the PE header. useful for offset calculations.
    PeExeHeader		_pe_header;         // The PE header structure for this file.
    // TBD!!!

    void load_header(std::istream &stream);
};

#endif  //_EXELIB_PEEXE_H_
