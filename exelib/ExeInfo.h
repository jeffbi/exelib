/// \file   ExeInfo.h
/// Classes and structures describing the NE section of a new-style executable.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_EXEINFO_H_
#define _EXELIB_EXEINFO_H_

#include <iosfwd>
#include <memory>
#include <vector>

#include "MZExe.h"
#include "NEExe.h"
#include "PEExe.h"
#include "readstream.h"

/// \brief  Possible values for the type of executable.
enum class ExeType
{
    Unknown = 0,
    MZ      = 0x5A4D,
    NE      = 0x454E,
    LE      = 0x454C,
    LX      = 0x584C,
    PE      = 0x4550
};


/// \brief  The executable file as a whole.
///         Contains data from the MZ header as well as from any "new" sections.
///
/// \c ExeInfo is the core object type for the exelib library. To explore an
/// executable, construct an \c ExeInfo object with an \c std::istream instance.
///
class ExeInfo
{
public:
    /// \brief Construct an \c ExeInfo object from a stream.
    /// \param stream   An \c std::istream instance from which to read.
    ///                 The stream must have been opened using binary mode.
    ExeInfo(std::istream &stream)
      : _mz_info{stream}
    {
        // if _mz_info's constructor succeeded, we know we at least have a MZ-type executable
        _type = ExeType::MZ;

        if (_mz_info.header().new_header_offset)    // we should have a new header at this offset in the file
        {
            uint16_t    two_byte_sig;
            uint32_t    four_byte_sig;

            // Read for both NE and PE signatures
            stream.seekg(_mz_info.header().new_header_offset);
            read(stream, &two_byte_sig);
            stream.seekg(_mz_info.header().new_header_offset);
            read(stream, &four_byte_sig);
            stream.seekg(_mz_info.header().new_header_offset);

            if (two_byte_sig == NeExeHeader::ne_signature)
            {
                _ne_info = std::make_unique<NeExeInfo>(stream, _mz_info.header().new_header_offset);
                _type = ExeType::NE;
            }
            else if (two_byte_sig == static_cast<uint16_t>(ExeType::LE) || two_byte_sig == static_cast<uint16_t>(ExeType::LX))
            {
                // LE and LX are valid new-header types, but they are not currently supported.
                _type = static_cast<ExeType>(two_byte_sig);
            }
            else if (four_byte_sig == PeExeHeader::pe_signature)
            {
               _pe_info = std::make_unique<PeExeInfo>(stream, _mz_info.header().new_header_offset);
               _type = ExeType::PE;
            }
            else
            {
                _type = ExeType::Unknown;
            }
        }
    }

    /// \brief  Return a value indicating the type of executable, such as MZ, NE, PE, etc.
    /// \return An \c ExeType enumeration.
    ExeType executable_type() const noexcept
    {
        return _type;
    }

    /// \brief  Return a pointer to the MZ part of the executable.
    ///
    /// The MZ part of an executable will always exist, so
    /// the returned pointer will always be non-null.
    const MzExeInfo *mz_part() const noexcept
    {
        return &_mz_info;
    }

    /// \brief  Return a pointer to the NE part of the executable, if it exists.
    ///
    /// The NE part of an executable will only exist if the executable is an NE type,
    /// so the returned pointer may be null.
    const NeExeInfo *ne_part() const noexcept
    {
        return _ne_info.get();
    }

    /// \brief  Return a pointer to the PE part of the executable, if it exists.
    ///
    /// The PE part of an executable will only exist if the executable is a PE type,
    /// so the returned pointer may be null.
    const PeExeInfo *pe_part() const noexcept
    {
        return _pe_info.get();
    }

private:
    ExeType                     _type{ExeType::Unknown};    // the type of the executable: MZ, NE, PE, etc.
    MzExeInfo                   _mz_info;
    std::unique_ptr<NeExeInfo>  _ne_info;        // "New" NE part. Might not exist, particularly for modern PE-style or old MS-DOS executables.
    std::unique_ptr<PeExeInfo>  _pe_info;        // Newer PE part. Might not exist, if the executable is old or REALLY old.
};

#endif  // _EXELIB_EXEINFO_H_
