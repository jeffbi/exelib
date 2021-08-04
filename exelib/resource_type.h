/// \file   resource_type.h
/// Provides an enumeration of resource types
/// 
/// \author Jeff Bienstadt
///

#ifndef _EXELIB_RESOURCE_TYPE_H_
#define _EXELIB_RESOURCE_TYPE_H_

#include <cstdint>

enum class ResourceType : uint16_t
{
    Cursor          = 1,
    Bitmap          = 2,
    Icon            = 3,
    Menu            = 4,
    Dialog          = 5,
    String          = 6,
    FontDir         = 7,
    Font            = 8,
    Accelerator     = 9,
    RCData          = 10,
    MessageTable    = 11,

    GroupCursor     = 12,
    GroupIcon       = 13,

    Version         = 16,
    DlgInclude      = 17,
    PlugPlay        = 19,
    VXD             = 20,
    AniCursor       = 21,
    AniIcon         = 22,
    HTML            = 23
};

#endif  //_EXELIB_RESOURCE_TYPE_H_
