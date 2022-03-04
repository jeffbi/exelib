#ifndef _STRING_HELPERS_H_
#define _STRING_HELPERS_H_

#include <optional>
#include <string>
#include <unordered_map>

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <resource_type.h>

inline std::optional<std::wstring> make_wide(const std::string &narrow)
{
    if (narrow.size() < static_cast<size_t>(std::numeric_limits<int>::max()) - 1)
    {
        std::wstring    wide_str{};

        if (narrow.size())
        {
            auto convert_result = MultiByteToWideChar(CP_UTF8, 0, narrow.c_str(), static_cast<int>(narrow.size()), NULL, 0);
            if (convert_result > 0)
            {
                wide_str.resize(convert_result);
                if (MultiByteToWideChar(CP_UTF8, 0, narrow.c_str(), static_cast<int>(narrow.size()), wide_str.data(), static_cast<int>(wide_str.size())) < 0)
                {
                    return {};
                }
            }
        }

        return wide_str;
    }

    return {};
}

inline std::wstring make_resource_type_name(uint16_t type)
{
    static std::unordered_map<uint16_t, const wchar_t *> predefined_resource_names =
        {
            {static_cast<uint16_t>(ResourceType::Cursor), L"CURSOR"},
            {static_cast<uint16_t>(ResourceType::Bitmap), L"BITMAP"},
            {static_cast<uint16_t>(ResourceType::Icon), L"ICON"},
            {static_cast<uint16_t>(ResourceType::Menu), L"MENU"},
            {static_cast<uint16_t>(ResourceType::Dialog), L"DIALOG"},
            {static_cast<uint16_t>(ResourceType::String), L"STRING"},
            {static_cast<uint16_t>(ResourceType::FontDir), L"FONTDIR"},
            {static_cast<uint16_t>(ResourceType::Font), L"FONT"},
            {static_cast<uint16_t>(ResourceType::Accelerator), L"ACCELERAOR"},
            {static_cast<uint16_t>(ResourceType::RCData), L"RCDATA"},
            {static_cast<uint16_t>(ResourceType::MessageTable), L"MESSAGE_TABLE"},
            {static_cast<uint16_t>(ResourceType::GroupCursor), L"GROUP_CURSOR"},
            {static_cast<uint16_t>(ResourceType::GroupIcon), L"GROUP_ICON"},

            {static_cast<uint16_t>(ResourceType::Version), L"VERSION"},
            {static_cast<uint16_t>(ResourceType::DlgInclude), L"DLGINCLUDE"},
            {static_cast<uint16_t>(ResourceType::PlugPlay), L"PLUGPLAY"},
            {static_cast<uint16_t>(ResourceType::VXD), L"VXD"},
            {static_cast<uint16_t>(ResourceType::AniCursor), L"ANICURSOR"},
            {static_cast<uint16_t>(ResourceType::AniIcon), L"ANIICON"},
            {static_cast<uint16_t>(ResourceType::HTML), L"HTML"}
        };

    if (type & 0x8000)
    {
        type &= ~0x8000;
        auto it = predefined_resource_names.find(type);
        if (it == predefined_resource_names.end())
            return L"<UNKNOWN>";
        else
            return it->second;
    }
    else
    {
        return L""; // this should ever happen because this function should never be called without the high bit set
                    //TODO: consider throwing an error instead
    }
}

#endif  //_STRING_HELPERS_H_
