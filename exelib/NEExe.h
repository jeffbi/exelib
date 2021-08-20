/// \file   NEExe.h
/// Classes and structures describing the NE section of a new-style executable.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_NEEXE_H_
#define _EXELIB_NEEXE_H_


#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

#include "LoadOptions.h"

/// \brief  Describes the new NE-style header
struct NeExeHeader
{
    /* 00 */    uint16_t    signature;              // 0x454E (NE)
    /* 02 */    int8_t      linker_version;         // linker version number
    /* 03 */    int8_t      linker_revision;        // linker revision number
    /* 04 */    uint16_t    entry_table_offset;     // offset to Entry Table
    /* 06 */    uint16_t    entry_table_size;       // number of bytes in Entry Table
    /* 08 */    uint32_t    checksum;               // 32 bit check sum for the file
    /* 0C */    uint16_t    flags;                  // flag word
    /* 0E */    uint16_t    auto_data_segment;      // segment number of automatic data segment
    /* 10 */    uint16_t    inital_heap;            // initial size, in bytes, of dynamic heap added to the data segment; 0 for no heap
    /* 12 */    uint16_t    initial_stack;          // initial size, in bytes, of stack added to the data segment
    /* 14 */    uint16_t    initial_IP;             // initial IP value
    /* 16 */    uint16_t    initial_CS;             // initial CS segment number
    /* 18 */    uint16_t    initial_SP;             // initial SP value
    /* 1A */    uint16_t    initial_SS;             // initial SS segment number
    /* 1C */    uint16_t    num_segment_entries;    // number of Segment Table entries
    /* 1E */    uint16_t    num_module_entries;     // number of entries in Module Reference Table
    /* 20 */    uint16_t    non_res_name_table_size;// size of non-resident name table (bytes)
    /* 22 */    uint16_t    segment_table_offset;   // offset of Segment Table
    /* 24 */    uint16_t    resource_table_offset;  // Offset of Resource Table
    /* 26 */    uint16_t    res_name_table_offset;  // offset of resident name table
    /* 28 */    uint16_t    module_table_offset;    // offset of Module Reference Table
    /* 2A */    uint16_t    import_table_offset;    // offset of Imported Names Table
    /* 2C */    uint32_t    non_res_name_table_pos; // absolute position of the Non-resident Names Table, from beginning of file
    /* 30 */    uint16_t    num_movable_entries;    // number of movable entries in Entry Table
    /* 32 */    uint16_t    alignment_shift_count;  // logical sector alignment shift count, log(base 2) of the segment sector size (default 9)
    /* 34 */    uint16_t    num_resource_entries;   // number of entries in the Resource Table
    /* 36 */    uint8_t     executable_type;        // type of executable. 0x02 = Windows (16 bit).
    /* 37 */    uint8_t     additional_flags;       // additional exe flags, for OS/2
    /* 38 */    uint16_t    gangload_offset;        // offset to return thunks or start of gangload area
    /* 3A */    uint16_t    gangload_size;          // offset to segment reference thunks or length of gangload area
    /* 3C */    uint16_t    min_code_swap_size;     // minimum code swap area size
    /* 3E */    uint16_t    expected_win_version;   // Expected Windows version number (minor first)

    static constexpr uint16_t   ne_signature{0x454E};
};

/// \brief  Values that the executable_type member of the \c NeExeHeader may contain
enum class NeExeType : uint8_t
{
    Unknown     = 0x00,
    OS_2        = 0x01,
    Windows     = 0x02,
    EuroDOS4    = 0x03,     // European MS-DOS 4.x
    Windows386  = 0x04,
    BOSS        = 0x05,     // Borland Operating System Services
    PharLap_OS2 = 0x81,     // PharLap 286|DOS-Extender, OS/2
    PharLap_Win = 0x82      // PharLap 286|DOS-Extender, Windows
};

/*
* The following two structures are not actually used in the code.
* They serve only as an indicator of what the two different types
* of entry in the entry table look like.
*/

/// \brief  Fixed-segment entry in the Entry Table
struct NeFixedEntry
{
    uint8_t     flags;
    uint16_t    segment_offset;
};

/// \brief  Moveable-segment entry in the Entry Table
struct NeMoveableEntry
{
    uint8_t     flags;
    uint16_t    INT3F;          // x86 INT 3F instruction bytes
    uint8_t     segment_number;
    uint16_t    segment_offset;
};


/// \brief  Entry in the Segment Table
struct NeSegmentEntry
{
    uint16_t    sector;
    uint16_t    length;
    uint16_t    flags;
    uint16_t    min_alloc;

    enum Flags : uint16_t
    {
        CodeSegment = 0x0000,
        DataSegment = 0x0001,
        Moveable    = 0x0010,
        Preload     = 0x0040,
        RelocInfo   = 0x0100,
        Discard     = 0xF000
    };
};

/// \brief  Entry in the Resource sub-table. Describes a single resource.
//          There are n of these for each resource type.
struct NeResource
{
    uint16_t                offset;     // absolute position in the file of the resource content.
    uint16_t                length;     // length of the resource content.
    uint16_t                flags;      // flag word
    uint16_t                id;         // if the high bit is set, an integer ID; otherwise an offset to a resource name.
    uint32_t                reserved;
    // the above items are what is in the file

    std::string             name;       // name, if any, of the resource, extracted from the name table.
    bool                    has_data {false};
    std::vector<uint8_t>    bits;
};

/// \brief  Entry in the Resource Table. Contains the type and number of resources.
///         There is one of these for each resource type (menu, string table, etc.)
struct NeResourceEntry
{
    uint16_t                    type;       // if the high bit is set, an integer type ID; otherwise an offset to a resource type name.
    uint16_t                    count;      // number of resources of this type
    uint32_t                    reserved;
    // the above items are what is in the file

    std::string                 type_name;  // name, if any, of the resource type, extracted from the name table.
    std::vector<NeResource>     resources;  // table of resource descriptors
};

/// \brief  Contains name data.
///         The Resident Name Table and the Non-resident Name Table
///         each store a name and an ordinal number.
struct NeName
{
    std::string     name;
    uint16_t        ordinal;
};

/// \brief  Contains information about the new "NE" section of an executable file.
class NeExeInfo
{
public:
    // Types
    using ByteContainer     = std::vector<uint8_t>;
    using ResourceTable     = std::vector<NeResourceEntry>;
    using SegmentTable      = std::vector<NeSegmentEntry>;
    using NameContainer     = std::vector<NeName>;
    using StringContainer   = std::vector<std::string>;

    /// \brief  Construct an \c NeExeInfo object from a stream.
    /// \param stream           An \c std::istream instance from which to read.
    /// \param header_location  Position in the file at which the NE portion begins.
    /// \param options          Flags indicating what portions of the file to load.
    NeExeInfo(std::istream &stream, size_t header_location, LoadOptions::Options options)
      : _header_position{header_location},
        _res_shift_count{0}
    {
        load_header(stream);

        load_entry_table(stream);
        load_segment_table(stream);
        load_resource_table(stream, options & LoadOptions::LoadResourceData);   // _res_shift_count is set here
        load_resident_name_table(stream);
        load_nonresident_name_table(stream);
        load_imported_name_table(stream);
        load_module_name_table(stream);
    }

    /// \brief  Return the file position of the NE header.
    size_t header_position() const noexcept
    {
        return _header_position;
    }

    /// \brief  Return a reference to the NE header.
    const NeExeHeader &header() const noexcept
    {
        return _header;
    }

    /// \brief  Return the alignmet shift count.
    uint16_t align_shift_count() const noexcept
    {
        return header().alignment_shift_count;
    }

    /// \brief  Return the shift count loaded from the Resource Table.
    uint16_t resource_shift_count() const noexcept
    {
        return _res_shift_count;
    }

    /// \brief  Return a reference to the Entry Table.
    const ByteContainer &entry_table() const noexcept
    {
        return _entry_table;
    }

    /// \brief  Return a reference to the Segment Table.
    const SegmentTable &segment_table() const noexcept
    {
        return _segment_table;
    }

    /// \brief  Return a reference to the Resource Table.
    const ResourceTable &resource_table() const noexcept
    {
        return _resource_table;
    }

    /// \brief  Return a reference to the Resident Names Table.
    const NameContainer &resident_names() const noexcept
    {
        return _resident_names;
    }

    /// \brief  Return a reference to the Nonresident Names Table.
    const NameContainer &nonresident_names() const noexcept
    {
        return _nonresident_names;
    }

    /// \brief  Return a reference to the Imported Names Table.
    const StringContainer &imported_names() const noexcept
    {
        return _imported_names;
    }

    /// \brief  Return a reference to the Module Names Table.
    const StringContainer &module_names() const noexcept
    {
        return _module_names;
    }

    /// \brief  Return the name of this module.
    /// \return A string containing the module name,
    ///         or an empty string if the name could not be retrieved.
    ///
    /// The module name is the first entry in the Resident Names Table, if any.
    std::string module_name() const
    {
        if (resident_names().size())
            return resident_names()[0].name;
        else
            return std::string();
    }

    /// \brief  Return the description of this module.
    /// \return A string containing the module description,
    ///         or an empty string if the description could not be retrieved.
    ///
    /// The module description is the first entry in the Nonresident Names Table, if any.
    std::string module_description() const
    {
        if (nonresident_names().size())
            return nonresident_names()[0].name;
        else
            return std::string();
    }

private:
    size_t          _header_position;   // absolute position in the file of the NE header. used for offset calculations
    uint16_t        _res_shift_count;   // shift count loaded from the Resource Table
    NeExeHeader     _header;            // the NE header structure for this file
    ByteContainer   _entry_table;       // the Entry Table
    SegmentTable    _segment_table;     // the Segment Table
    ResourceTable   _resource_table;    // the Resource Table
    NameContainer   _resident_names;    // the Resident Names Table
    NameContainer   _nonresident_names; // the Non-resident Names Table
    StringContainer _imported_names;    // the Imported Names Table
    StringContainer _module_names;      // the Module Names Table

    void load_header(std::istream &stream);
    void load_entry_table(std::istream &stream);
    void load_segment_table(std::istream &stream);
    void load_resource_table(std::istream &stream, bool load_raw_data);
    void load_resident_name_table(std::istream &stream);
    void load_imported_name_table(std::istream &stream);
    void load_module_name_table(std::istream &stream);
    void load_nonresident_name_table(std::istream &stream);
};

#endif  //_EXELIB_PEEXE_H_
