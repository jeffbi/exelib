/// \file   MZExe.h
/// Classes and structures describing the MZ section of an executable.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_MZEXE_H_
#define _EXELIB_MZEXE_H_

#include <cstdint>
#include <iosfwd>
#include <vector>

#include "LoadOptions.h"


/// \brief  Describes the MZ header. These are the first bytes in an EXE executable.
struct MzExeHeader
{
    /* 00 */    uint16_t    signature;              // 0x5A4D (MZ)
    /* 02 */    uint16_t    bytes_on_last_page;     // bytes on last page
    /* 04 */    uint16_t    num_pages;              // number of 512 byte pages, whole and partial
    /* 06 */    uint16_t    num_relocation_items;
    /* 08 */    uint16_t    header_size;            // in 16 byte paragraphs
    /* 0A */    uint16_t    min_allocation;         // number of paragraphs required
    /* 0C */    uint16_t    requested_allocation;   // number of paragraphs requested
    /* 0E */    uint16_t    initial_SS;             // relocatable segment address for SS
    /* 10 */    uint16_t    initial_SP;             // initial value for SP
    /* 12 */    uint16_t    checksum;
    /* 14 */    uint16_t    initial_IP;             // initial value for IP
    /* 16 */    uint16_t    initial_CS;             // relocatable segment address for CS
    /* 18 */    uint16_t    relocation_table_pos;   // absolute offset to the relocation table
    /* 1A */    uint16_t    overlay;                // value used for overlay management. zero indicates main executable
    /* 1C */    uint16_t    reserved1[4];
    /* 24 */    uint16_t    oem_ID;
    /* 26 */    uint16_t    oem_info;
    /* 28 */    uint16_t    reserved2[10];
    /* 3C */    uint32_t    new_header_offset;      // might be any of NE, LE, LX, or PE header, or nothing

    static constexpr uint16_t   mz_signature{0x5A4D};
};

/// \brief  Describes an entry in the MZ executable's Relocation Table
struct MzRelocPointer
{
    uint16_t    offset;
    uint16_t    segment;
};

/// \brief  Contains information about the "MZ" section of an executable file.
///
/// The MZ section is at the beginning of every executable, and must exist.
class MzExeInfo
{
public:
    /// \brief  Construct an \c MzExeInfo object from a stream.
    ///
    /// \param stream   An \c std::istream instance from which to read
    /// \param options  Flags indicating what portions of the file to load.
    MzExeInfo(std::istream &stream, LoadOptions::Options options)
    {
        load_header(stream);
        load_relocation_table(stream, _header.relocation_table_pos, _header.num_relocation_items);
    }

    /// \brief  Return a reference to the MZ header.
    const MzExeHeader &header() const noexcept
    {
        return _header;
    }

    /// \brief  Return a reference to the Relocation Table.
    const std::vector<MzRelocPointer> &relocation_table() const noexcept
    {
        return _relocation_table;
    }

private:
    MzExeHeader                 _header;
    std::vector<MzRelocPointer> _relocation_table;

    void load_header(std::istream &stream);
    void load_relocation_table(std::istream &stream, uint16_t location, uint16_t count);
};

#endif  //_EXELIB_MZEXE_H_
