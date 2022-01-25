/// \file   LoadOptions.h
/// Defines a mechanism for specifying options for loading files.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_LOADOPTIONS_H_
#define _EXELIB_LOADOPTIONS_H_

/// \brief  Bitflags for specifying load options.
///
/// Some executable files can be quite large. These flags allow the user to load
/// only certain subsets of the available information.
class LoadOptions
{
public:
    using Options = uint32_t;

    static constexpr Options LoadBasics             = 0x0000;   ///< Headers tables, etc. are always loaded, so providing this is optional
    static constexpr Options LoadResourceData       = 0x0001;   ///< Load raw data from resources in NE or PE files.
    static constexpr Options LoadSegmentData        = 0x0002;   ///< Load raw data from segments in NE files.
    static constexpr Options LoadSectionData        = 0x0004;   ///< Load raw data from sections in PE files.
    static constexpr Options LoadMzRelocationData   = 0x0008;   ///< Load Relocation Table from MZ files
    static constexpr Options LoadDebugData          = 0x0010;   ///< Load the raw debug data. Some data will be loaded always.
    static constexpr Options LoadCli                = 0x0020;   ///< Load the CLI information, if the module is managed code.
    static constexpr Options LoadCliMetadata        = 0x0060;   ///< Load the CLI metadata. Implies loading CLI information.
    static constexpr Options LoadCliMetadataStreams = 0x00E0;   ///< Load the CLI metadata tables from the CLI #~ heap. Implies loading CLI metadata.
    static constexpr Options LoadCliMetadataTables  = 0x01E0;   ///< Load the CLI metadata tables from the CLI #~ heap. Implies loading CLI metadata streams.
    static constexpr Options LoadAllCli             = 0x01E0;   ///< Load all the CLI information, including the metadata and tables.
    static constexpr Options LoadAllData            = 0xFFFF;   ///< Load all the data from an executable image.
                                                                //This value could change if more flags are added above.
};

#endif  // _EXELIB_LOADOPTIONS_H_
