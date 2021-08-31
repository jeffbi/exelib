/// \file   LoadOptions.h
/// Defines a mechanism for specifying options for loading files.
///
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_LOADOPTIONS_H_
#define _EXELIB_LOADOPTIONS_H_

class LoadOptions
{
public:
    using Options = int;

    static constexpr Options LoadBasics             = 0x0000;   // Headers tables, etc. are always loaded, so providing this is optional
    static constexpr Options LoadResourceData       = 0x0001;   // Load raw data from resources in NE or PE files.
    static constexpr Options LoadSegmentData        = 0x0002;   // Load raw data from segments in NE files.
    static constexpr Options LoadSectionData        = 0x0004;   // Load raw data from sections in PE files.
    static constexpr Options LoadMzRelocationData   = 0x0008;   // Load Relocation Table from MZ files
    static constexpr Options LoadDebugData          = 0x0010;   // Load the raw debug data. Some data will be loaded always.
    static constexpr Options LoadAllData            = 0x00FF;   // This value could change if more flags are added above.
};

#endif  // _EXELIB_LOADOPTIONS_H_
