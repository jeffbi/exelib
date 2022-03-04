#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <utility>

#include <tchar.h>
#include <strsafe.h>

//#include "pch.h"    // pre-compiled headers
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "MainList.h"
#include "FileInfo.h"
#include "string_helpers.h"

#include <ExeInfo.h>

// This is a very rudimentary RAII class.
// I would not use it as is in production code.
class WaitCursor
{
public:
    WaitCursor() noexcept
    {
        old_cursor = SetCursor(LoadCursor(nullptr, IDC_WAIT));
    }
    WaitCursor(const WaitCursor &) = delete;
    WaitCursor(WaitCursor &&) = delete;
    WaitCursor &operator=(const WaitCursor &) = delete;
    WaitCursor &operator=(WaitCursor &&) = delete;

    ~WaitCursor()
    {
        SetCursor(old_cursor);
    }

private:
    HCURSOR old_cursor{nullptr};
};

namespace {
void format_systime(STRSAFE_LPWSTR destination, size_t size, const SYSTEMTIME &systime)
{
    static constexpr const wchar_t *days[] {L"Sunday", L"Monday", L"Tuesday", L"Wednesday", L"Thursday", L"Friday", L"Saturday"};
    static constexpr const wchar_t *months[] {
        L"January",
        L"February",
        L"March",
        L"April",
        L"May",
        L"June",
        L"July",
        L"August",
        L"September",
        L"October",
        L"November",
        L"December"
    };
    StringCbPrintf(destination, size, L"%s, %02hu %s %04hu, %02hu:%02hu:%02hu",
                   days[systime.wDayOfWeek],
                   systime.wDay, months[systime.wMonth - 1], systime.wYear,
                   systime.wHour, systime.wMinute, systime.wSecond);
}

void format_filetime(STRSAFE_LPWSTR destination, size_t size, const FILETIME &filetime)
{
    SYSTEMTIME  systime;
    SYSTEMTIME  localtime;

    FileTimeToSystemTime(&filetime, &systime);
    SystemTimeToTzSpecificLocalTime(NULL, &systime, &localtime);
    format_systime(destination, size, localtime);

}

inline void guid_to_string(const Guid &guid, LPWSTR destination, size_t size)
{
    StringCbPrintf(destination, size, L"{%08X-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX}",
                   guid.data1, guid.data2, guid.data3,
                   guid.data4[0],guid.data4[1],guid.data4[2],guid.data4[3],guid.data4[4],guid.data4[5],guid.data4[6],guid.data4[7]);
}

}   // anonymous namespace


void MainList::populate_file_info(const FileInfo &info)
{
    clear();

    auto    size{std::max(info.path.size() + 1, 256ull)};
    std::vector<TCHAR>  v(size, 0);
    TCHAR              *text_buffer{v.data()};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer;

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer, size, L"Property");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer, size, L"Value");
    lvc.cx = 300;
    insert_column(1, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer;
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer, size, L"File path");
    insert_item(&lvi);
    _tcscpy_s(text_buffer, size, info.path.c_str());
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer, size, L"File size");
    insert_item(&lvi);
    StringCbPrintf(text_buffer, size, L"%I64d", info.size.QuadPart);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer, size, L"Created");
    insert_item(&lvi);
    if (!(info.create_time.dwHighDateTime == 0 && info.create_time.dwLowDateTime != 0))
    {
        format_filetime(text_buffer, size, info.create_time);
        lvi.iSubItem = 1;
        set_item(&lvi);
    }

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer, size, L"Modified");
    insert_item(&lvi);
    if (!(info.write_time.dwHighDateTime == 0 && info.write_time.dwLowDateTime != 0))
    {
        format_filetime(text_buffer, size, info.write_time);
        lvi.iSubItem = 1;
        set_item(&lvi);
    }

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer, size, L"Accessed");
    insert_item(&lvi);
    if (!(info.access_time.dwHighDateTime == 0 && info.access_time.dwLowDateTime != 0))
    {
        format_filetime(text_buffer, size, info.access_time);
        lvi.iSubItem = 1;
        set_item(&lvi);
    }
}

void MainList::populate_mz(const MzExeHeader &header)
{
    clear();

    //TCHAR   text_buffer[80]{0};
    std::array<wchar_t, 80> text_buffer{0};
    //constexpr size_t        size{text_buffer.size()};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 100;
    insert_column(1, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.iSubItem = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.signature);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Bytes on last page");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.bytes_on_last_page);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of pages");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.num_pages);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of relocation items");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.num_relocation_items);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Header size, in 16-byte paragraphs");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.header_size);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of paragraphs required");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.min_allocation);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of paragraphs requested");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.requested_allocation);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial SS");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.initial_SS);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial SP");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.initial_SP);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Checksum");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.checksum);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial IP");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.initial_IP);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial CS");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.initial_CS);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Relocation table position");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.relocation_table_pos);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Overlay");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.overlay);
    lvi.iSubItem = 1;
    set_item(&lvi);

    for (int i = 0; i < 4; ++i)
    {
        ++lvi.iItem;
        lvi.iSubItem = 0;
        _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Reserved");
        insert_item(&lvi);
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.reserved1[i]);
        lvi.iSubItem = 1;
        set_item(&lvi);
    }

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OEM ID");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.oem_ID);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OEM info");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.oem_info);
    lvi.iSubItem = 1;
    set_item(&lvi);

    for (int i=0; i < 10; ++i)
    {
        ++lvi.iItem;
        lvi.iSubItem = 0;
        _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Reserved");
        insert_item(&lvi);
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.reserved2[i]);
        lvi.iSubItem = 1;
        set_item(&lvi);
    }

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"New header offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.new_header_offset);
    lvi.iSubItem = 1;
    set_item(&lvi);
}



void MainList::populate_ne(const NeExeInfo &info)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 300;
    insert_column(1, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), info.header().flags & 0x8000 ? L"Library" : L"Module");
    insert_item(&lvi);
    auto module_name{make_wide(info.module_name()).value_or(L"")};
    lvi.pszText = module_name.data();
    lvi.iSubItem = 1;
    set_item(&lvi);
    lvi.pszText = text_buffer.data();

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Description");
    insert_item(&lvi);
    auto module_desc{make_wide(info.module_description()).value_or(L"")};
    lvi.pszText = module_desc.data();
    lvi.iSubItem = 1;
    set_item(&lvi);
    lvi.pszText = text_buffer.data();

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Expected Windows version");
    insert_item(&lvi);
    unsigned ver_major{(static_cast<unsigned>(info.header().expected_win_version) >> 8) & 0xFF};
    unsigned ver_minor{static_cast<unsigned>(info.header().expected_win_version) & 0xFF};
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u.%u", ver_major, ver_minor);
    lvi.iSubItem = 1;
    set_item(&lvi);
}


void MainList::populate_ne_header(const NeExeInfo &info)
{
    clear();


    std::array<wchar_t, 200>    text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 100;
    insert_column(1, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 2;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Meaning");
    lvc.cx = 200;
    insert_column(2, &lvc);


    // Insert the items
    const auto &header{info.header()};

    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.signature);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Linker version");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hhu", header.linker_version);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Linker revision");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hhu", header.linker_revision);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Entry table offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.entry_table_offset);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Entry table size in bytes");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.entry_table_size);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Checksum");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.checksum);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.flags);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Auto data segment");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.auto_data_segment);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial heap size");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.inital_heap);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial stack size");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.initial_stack);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial IP value");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.initial_IP);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial CS value");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.initial_CS);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial SP value");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.initial_SP);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initial SS value");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.initial_SS);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of segment entries");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.num_segment_entries);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of module entries");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.num_module_entries);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Non-resident name table size");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.non_res_name_table_size);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Segment table offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.segment_table_offset);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Resource table offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.resource_table_offset);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Resident name table offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.res_name_table_offset);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Module table offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.module_table_offset);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Import table offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.import_table_offset);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Non-resident names table position");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.non_res_name_table_pos);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of movable entries");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.num_movable_entries);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Alignment shift count");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.alignment_shift_count);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of resource entries");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.num_resource_entries);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Type of executable");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%02hhX", header.executable_type);
    lvi.iSubItem = 1;
    set_item(&lvi);
    //TODO: Add type text in sub-item

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Additional flags");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%02hhX", header.additional_flags);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Gangload offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.gangload_offset);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Gangload size");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.gangload_size);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Minimum code swap size");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.min_code_swap_size);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Expected Windows version");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.expected_win_version);
    lvi.iSubItem = 1;
    set_item(&lvi);

}

void MainList::populate_ne_entry_table(const NeExeInfo::EntryTable &table)
{
    clear();


    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Bundle");
    lvc.cx = 100;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Segment Type");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Entry Count");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;


    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;
    size_t  n_bundle{1};
    for (const auto &bundle : table)
    {
        lvi.iSubItem = 0;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"Bundle %llu", n_bundle++);
        insert_item(&lvi);

        ++lvi.iSubItem;
        _tcscpy_s(text_buffer.data(), text_buffer.size(), bundle.movable() ? L"MOVEABLE" : L"FIXED");
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%llu", bundle.entries().size());
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_ne_entry_bundle(const NeEntryBundle &bundle)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Ordinal");
    lvc.cx = 100;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Segment");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Offset");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Description");
    lvc.cx = 200;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;


    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;
    for (const auto &entry : bundle.entries())
    {
        lvi.iSubItem = 0;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", entry.ordinal());
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%02hX", entry.segment());
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", entry.offset());
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%02hhX", entry.flags());
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            std::wstring str{bundle.movable() ? L"MOVEABLE" : L"FIXED"};
            if (entry.is_exported())
                str += L" EXPORTED";
            if (entry.is_shared_data())
                str += L" SHARED-DATA";
            _tcscpy_s(text_buffer.data(), text_buffer.size(), str.c_str());
        }
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_ne_segment_table(const NeExeInfo::SegmentTable &table, uint16_t alignment_shift)
{
    clear();


    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Segment Type");
    lvc.cx = 100;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Sector Offset");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Length");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Min. Alloc");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Meaning");
    lvc.cx = 250;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;


    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;
    for (const auto &segment : table)
    {
        lvi.iSubItem = 0;
        _tcscpy_s(text_buffer.data(), text_buffer.size(), segment.flags & NeSegmentEntry::DataSegment ? L"DATA" : L"CODE");
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", static_cast<uint32_t>(segment.sector) << alignment_shift);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", segment.length);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", segment.min_alloc);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", segment.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            std::wstring    str{(segment.flags & NeSegmentEntry::Preload) ? L"PRELOAD " : L""};

            if (segment.flags & NeSegmentEntry::RelocInfo)
                str += L"RELOCINFO ";
            if (segment.flags & NeSegmentEntry::Moveable)
                str += L"MOVEABLE ";
            if (segment.flags & NeSegmentEntry::Discard)
                str += L"DISCARDABLE";
            lvi.pszText = str.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iItem;
    }

}

// used for both Resident and Non-Resident name tables.
void MainList::populate_ne_names_table(const NeExeInfo::NameContainer &names)
{
    clear();


    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Ordinal");
    lvc.cx = 100;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;


    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;
    for (const auto &name : names)
    {
        lvi.iSubItem = 0;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", name.ordinal);
        insert_item(&lvi);

        ++lvi.iSubItem;
        {
            auto str{make_wide(name.name).value()};

            lvi.pszText = str.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iItem;
    }
}

void MainList::populate_ne_strings(const NeExeInfo::StringContainer &strings, bool show_length)
{
    clear();


    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 100;
    insert_column(0, &lvc);

    if (show_length)
    {
        lvc.fmt = LVCFMT_RIGHT;
        ++lvc.iSubItem;
        _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Length");
        lvc.cx = 100;
        insert_column(lvc.iSubItem, &lvc);
    }


    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;


    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;
    for (const auto &name : strings)
    {
        std::wstring str{make_wide(name).value_or(L"")};

        lvi.iSubItem = 0;
        lvi.pszText = str.data();
        insert_item(&lvi);
        lvi.pszText = text_buffer.data();

        if (show_length)
        {
            ++lvi.iSubItem;
            StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%I64u", name.size());
            set_item(&lvi);
        }


        ++lvi.iItem;
    }
}

void MainList::populate_ne_resource_table([[maybe_unused]]const NeExeInfo::ResourceTable &resources) noexcept
{
    clear();


    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Resource Type");
    lvc.cx = 160;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Count");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;


    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;
    for (const auto &entry : resources)
    {
        std::wstring    type_name{entry.type & 0x8000 ? make_resource_type_name(entry.type) : make_wide(entry.type_name).value_or(L"")};


        lvi.iSubItem = 0;
        lvi.pszText = type_name.data();
        insert_item(&lvi);
        lvi.pszText = text_buffer.data();

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", entry.count);
        set_item(&lvi);


        ++lvi.iItem;
    }
}

void MainList::populate_ne_resource_entry(const NeResourceEntry &entry, uint16_t shift_count)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Offset");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Length");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"ID");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Reserved");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;
    for (const auto &resource : entry.resources)
    {
        lvi.iSubItem = 0;
        _tcscpy_s(text_buffer.data(), text_buffer.size(), make_wide(resource.name).value_or(L"").c_str());
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", resource.offset << shift_count);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", static_cast<unsigned>(resource.length << shift_count));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", resource.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", resource.id);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", resource.reserved);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_ne_resource(const NeResource &resource, uint16_t shift_count)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 100;
    insert_column(1, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 2;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Meaning");
    lvc.cx = 200;
    insert_column(2, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    insert_item(&lvi);
    _tcscpy_s(text_buffer.data(), text_buffer.size(), resource.id & 0x8000 ? L"" : make_wide(resource.name).value_or(L"").c_str());
    lvi.iSubItem = 1;
    set_item(&lvi);
    if (resource.id & 0x8000)
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"Integer resource ID %hu", resource.id & ~0x8000u);
    else
        _tcscpy_s(text_buffer.data(), text_buffer.size(), L"String resource ID");
    lvi.iSubItem = 2;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04X", static_cast<unsigned>(resource.offset << shift_count));
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Length");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", static_cast<unsigned>(resource.length << shift_count));
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", resource.flags);
    lvi.iSubItem = 1;
    set_item(&lvi);
    std::wstring    flags;
    if (resource.flags & 0x10)
        flags = L"MOVEABLE ";
    if (resource.flags & 0x20)
        flags += L"PURE ";
    if (resource.flags & 0x40)
        flags +=  L"PRELOAD";
    ///NOTE: There are other bits in the flags word, but I haven't found documentation for them.

    lvi.iSubItem = 2;
    lvi.pszText = flags.data();
    set_item(&lvi);
    lvi.pszText = text_buffer.data();

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"ID");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", resource.id);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"reserved");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", resource.reserved);
    lvi.iSubItem = 1;
    set_item(&lvi);

}


void MainList::populate_pe(const PeExeInfo &peinfo)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 100;
    insert_column(1, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.iSubItem = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", peinfo.header().signature);
    lvi.iSubItem = 1;
    set_item(&lvi);
}

namespace {

// Helper to make the target_machine member of the PE header into a string for output.
const wchar_t *get_pe_target_machine_string(uint16_t machine_type) noexcept
{
    //TODO: Maybe use an unordered_map here?
    using ut = std::underlying_type<PeImageFileHeader::MachineType>::type;

    switch (machine_type)
    {
        case static_cast<ut>(PeImageFileHeader::MachineType::Unknown):
            return L"Unknown";
        case static_cast<ut>(PeImageFileHeader::MachineType::AM33):
            return L"Matsushita AM33";
        case static_cast<ut>(PeImageFileHeader::MachineType::AMD64):
            return L"x64";
        case static_cast<ut>(PeImageFileHeader::MachineType::ARM):
            return L"ARM little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::ARM64):
            return L"ARM64 little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::ARMNT):
            return L"ARM Thumb-2 little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::EBC):
            return L"EFI byte code";
        case static_cast<ut>(PeImageFileHeader::MachineType::I386):
            return L"Intel 386 or later processors and compatible processors";
        case static_cast<ut>(PeImageFileHeader::MachineType::IA64):
            return L"Intel Itanium processor family";
        case static_cast<ut>(PeImageFileHeader::MachineType::M32R):
            return L"Mitsubishi M32R little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::MIPS16):
            return L"MIPS16";
        case static_cast<ut>(PeImageFileHeader::MachineType::MIPSFPU):
            return L"MIPS with FPU";
        case static_cast<ut>(PeImageFileHeader::MachineType::MIPSFPU16):
            return L"MIPS16 with FPU";
        case static_cast<ut>(PeImageFileHeader::MachineType::PowerPC):
            return L"Power PC little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::PowerPCFP):
            return L"Power PC with floating point support";
        case static_cast<ut>(PeImageFileHeader::MachineType::R4000):
            return L"MIPS little endian";
        case static_cast<ut>(PeImageFileHeader::MachineType::RISCV32):
            return L"RISC-V 32-bit address space";
        case static_cast<ut>(PeImageFileHeader::MachineType::RISCV64):
            return L"RISC-V 64-bit address space";
        case static_cast<ut>(PeImageFileHeader::MachineType::RISCV128):
            return L"RISC-V 128-bit address space";
        case static_cast<ut>(PeImageFileHeader::MachineType::SH3):
            return L"Hitachi SH3";
        case static_cast<ut>(PeImageFileHeader::MachineType::SH3DSP):
            return L"Hitachi SH3 DSP";
        case static_cast<ut>(PeImageFileHeader::MachineType::SH4):
            return L"Hitachi SH4";
        case static_cast<ut>(PeImageFileHeader::MachineType::SH5):
            return L"Hitachi SH5";
        case static_cast<ut>(PeImageFileHeader::MachineType::Thumb):
            return L"Thumb";
        case static_cast<ut>(PeImageFileHeader::MachineType::WCEMIPSv2):
            return L"MIPS little-endian WCE v2";
        default:
            return L"machine type no recogized";
    }
}

}   // anonymous namespace

void MainList::populate_pe_file_header(const PeImageFileHeader &header)
{
    clear();

    std::array<wchar_t, 200>    text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 100;
    insert_column(1, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 2;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Meaning");
    lvc.cx = 200;
    insert_column(2, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.iSubItem = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.signature);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Target machine");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.target_machine);
    lvi.iSubItem = 1;
    set_item(&lvi);
    _tcscpy_s(text_buffer.data(), text_buffer.size(), get_pe_target_machine_string(header.target_machine));
    lvi.iSubItem = 2;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of sections");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.num_sections);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Timestamp");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04X", header.timestamp);
    lvi.iSubItem = 1;
    set_item(&lvi);
    const time_t    tt{header.timestamp};
    tm              tm;
    gmtime_s(&tm, &tt);
    std::wcsftime(text_buffer.data(), text_buffer.size(), L"%c", &tm);
    lvi.iSubItem = 2;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Symbol table offset");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.symbol_table_offset);
    lvi.iSubItem = 1;
    set_item(&lvi);
    if (header.symbol_table_offset == 0)
    {
        _tcscpy_s(text_buffer.data(), text_buffer.size(), L"No symbol table");
        lvi.iSubItem = 2;
        set_item(&lvi);
    }

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of symbols");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.num_symbols);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of optional header");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04X", header.optional_header_size);
    lvi.iSubItem = 1;
    set_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u bytes", header.optional_header_size);
    lvi.iSubItem = 2;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Characteristics");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.characteristics);
    lvi.iSubItem = 1;
    set_item(&lvi);

    static constexpr std::pair<PeImageFileHeader::Characteristics, const wchar_t *> characteristics[] {
        {PeImageFileHeader::Characteristics::ExecutableImage, L"EXECUTABLE_IMAGE"},
        {PeImageFileHeader::Characteristics::RelocsStripped, L"RELOCS_STRIPPED"},
        {PeImageFileHeader::Characteristics::LineNumsStripped, L"LINE_NUMS_STRIPPED"},
        {PeImageFileHeader::Characteristics::LocalSymsStripped, L"LOCAL_SYMS_STRIPPED"},
        {PeImageFileHeader::Characteristics::AggressiveWsTrim, L"AGGRESSIVE_WS_TRIM"},
        {PeImageFileHeader::Characteristics::LargeAddressAware, L"LARGE_ADDRESS_AWARE"},
        {PeImageFileHeader::Characteristics::BytesReversedLO, L"BYTES_REVERSED_LO"},
        {PeImageFileHeader::Characteristics::Machine32Bit, L"MACHINE_32BIT"},
        {PeImageFileHeader::Characteristics::DebugStripped, L"DEBUG_STRIPPED"},
        {PeImageFileHeader::Characteristics::RemovableRunFromSwap, L"REMOVABLE_RUN_FROM_SWAP"},
        {PeImageFileHeader::Characteristics::NetRunFromSwap, L"NET_RUN_FROM_SWAP"},
        {PeImageFileHeader::Characteristics::System, L"SYSTEM"},
        {PeImageFileHeader::Characteristics::DLL, L"DLL"},
        {PeImageFileHeader::Characteristics::UPSystemOnly, L"UP_SYSTEM_ONLY"},
        {PeImageFileHeader::Characteristics::BytesReversedHI, L"BYTES_REVERSED_HI"},
    };
    std::wostringstream stream;
    // list characteristics
    for (const auto &pair : characteristics)
        if (header.characteristics & static_cast<std::underlying_type<PeImageFileHeader::Characteristics>::type>(pair.first))
            stream << pair.second << L' ';

    _tcscpy_s(text_buffer.data(), text_buffer.size(), stream.str().c_str());
    lvi.iSubItem = 2;
    set_item(&lvi);
}

namespace {

// Helper to make the subsystem member of the PE optional header into a string for output.
const wchar_t *get_subsystem_name(uint16_t subsystem) noexcept
{
    using ut = std::underlying_type<PeSubsystem>::type;

    switch (subsystem)
    {
        case static_cast<ut>(PeSubsystem::Unknown):
            return L"An unknown subsystem";
        case static_cast<ut>(PeSubsystem::Native):
            return L"Device drivers and native Windows processes";
        case static_cast<ut>(PeSubsystem::Windows_GUI):
            return L"Windows graphical user interface (GUI)";
        case static_cast<ut>(PeSubsystem::Windows_CUI):
            return L"The Windows character user interface (CUI)";
        case static_cast<ut>(PeSubsystem::OS2_CUI):
            return L"The OS/2 character user interface (CUI)";
        case static_cast<ut>(PeSubsystem::Posix_CUI):
            return L"The Posix character user interface (CUI)";
        case static_cast<ut>(PeSubsystem::NativeWindows):
            return L"Native Win9x driver";
        case static_cast<ut>(PeSubsystem::WindowsCE_GUI):
            return L"Windows CE";
        case static_cast<ut>(PeSubsystem::EfiApplication):
            return L"An EFI application";
        case static_cast<ut>(PeSubsystem::EfiBootServiceDriver):
            return L"An EFI driver with boot services";
        case static_cast<ut>(PeSubsystem::EfiRuntimeDriver):
            return L"An EFI driver with run-time services";
        case static_cast<ut>(PeSubsystem::EfiROM):
            return L"An EFI ROM image";
        case static_cast<ut>(PeSubsystem::XBox):
            return L"Xbox";
        case static_cast<ut>(PeSubsystem::WindowsBootApplication):
            return L"Windows boot application";
        case static_cast<ut>(PeSubsystem::XBoxCodeCatalog):
            return L"Xbox code catalog";
        default:
            return L"Unrecognized subsystem";
    }
}

}   // anonymous namespace

void MainList::populate_pe_optional_header32(const PeOptionalHeader32 &header)
{
    //TCHAR   text_buffer[80]{};
    //constexpr size_t size{sizeof(text_buffer) / sizeof(text_buffer[0])};
    std::array<wchar_t, 80> text_buffer{0};

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = populate_pe_optional_header_base(header);
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Base of data");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.magic);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Image base");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.image_base);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Section alignment");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.section_alignment);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"File alignment");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.file_alignment);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS version major");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.os_version_major);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS version minor");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.os_version_minor);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Image version major");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.image_version_major);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Image version minor");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.image_version_minor);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Subsystem version major");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.subsystem_version_major);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Subsystem version minor");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.subsystem_version_minor);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Win32 version value");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.win32_version_value);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of image");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.size_of_image);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of headers");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.size_of_headers);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Checksum");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.checksum);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Subsystem");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.subsystem);
    lvi.iSubItem = 1;
    set_item(&lvi);
    _tcscpy_s(text_buffer.data(), text_buffer.size(), get_subsystem_name(header.subsystem));
    lvi.iSubItem = 2;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"DLL characteristics");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.dll_characteristics);
    lvi.iSubItem = 1;
    set_item(&lvi);
    //TODO: Characteristics subitem



    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of stack to reserve");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.size_of_stack_reserve);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of stack to commit");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.size_of_stack_commit);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of local heap space to reserve");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.size_of_heap_reserve);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of local heap space to commit");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.size_of_heap_commit);
    lvi.iSubItem = 1;
    set_item(&lvi);



    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Loader flags");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.loader_flags);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of RVAs and sizes");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.num_rva_and_sizes);
    lvi.iSubItem = 1;
    set_item(&lvi);
}

void MainList::populate_pe_optional_header64(const PeOptionalHeader64 &header)
{
    std::array<wchar_t, 80> text_buffer{0};

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = populate_pe_optional_header_base(header);
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Image base");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%016I64X", header.image_base);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Section alignment");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.section_alignment);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"File alignment");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.file_alignment);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS version major");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.os_version_major);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS version minor");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.os_version_minor);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Image version major");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.image_version_major);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Image version minor");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.image_version_minor);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Subsystem version major");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.subsystem_version_major);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Subsystem version minor");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.subsystem_version_minor);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Win32 version value");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.win32_version_value);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of image");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.size_of_image);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of headers");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.size_of_headers);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Checksum");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.checksum);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Subsystem");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.subsystem);
    lvi.iSubItem = 1;
    set_item(&lvi);
    _tcscpy_s(text_buffer.data(), text_buffer.size(), get_subsystem_name(header.subsystem));
    lvi.iSubItem = 2;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"DLL characteristics");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.dll_characteristics);
    lvi.iSubItem = 1;
    set_item(&lvi);
    //TODO: Characteristics subitem



    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of stack to reserve");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%016I64X", header.size_of_stack_reserve);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of stack to commit");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%016I64X", header.size_of_stack_commit);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of local heap space to reserve");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%016I64X", header.size_of_heap_reserve);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size of local heap space to commit");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%016I64X", header.size_of_heap_commit);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Loader flags");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.loader_flags);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of RVAs and sizes");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.num_rva_and_sizes);
    lvi.iSubItem = 1;
    set_item(&lvi);
}

int MainList::populate_pe_optional_header_base(const PeOptionalHeaderBase &header)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 100;
    insert_column(1, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 2;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Meaning");
    lvc.cx = 200;
    insert_column(2, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Magic number");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.magic);
    lvi.iSubItem = 1;
    set_item(&lvi);
    switch (header.magic)
    {
        case 0x010B:
            _tcscpy_s(text_buffer.data(), text_buffer.size(), L"PE32 (32 bit)");
            break;

        case 0x0107:
            _tcscpy_s(text_buffer.data(), text_buffer.size(), L"ROM image");
            break;

        case 0x020B:
            _tcscpy_s(text_buffer.data(), text_buffer.size(), L"PE32+ (64 bit)");
            break;

        default:
            _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Unrecognized value");
            break;
    }
    lvi.iSubItem = 2;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Linker version major");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hhu", static_cast<unsigned int>(header.linker_version_major));
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Linker version minor");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hhu", static_cast<unsigned int>(header.linker_version_minor));
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Code size");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.code_size);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Initialized data size");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.initialized_data_size);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Uninitialized data size");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.uninitialized_data_size);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Address of entry point");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.address_of_entry_point);
    lvi.iSubItem = 1;
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Base of code");
    insert_item(&lvi);
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.base_of_code);
    lvi.iSubItem = 1;
    set_item(&lvi);

    return lvi.iItem + 1;
}

void MainList::populate_pe_data_directory(const PeExeInfo &peinfo)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Entry");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RVA");
    lvc.cx = 100;
    insert_column(1, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 2;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size");
    lvc.cx = 100;
    insert_column(2, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 3;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Section");
    lvc.cx = 100;
    insert_column(3, &lvc);


    static constexpr const wchar_t *data_table_names[]
        {
            L"Export Table",
            L"Import Table",
            L"Resource Table",
            L"Exception Table",
            L"Certificate Table",
            L"Base Relocation Table",
            L"Debug",
            L"Architecture",
            L"Global Pointer",
            L"Thread Local Storage Table",
            L"Load Configuration Table",
            L"Bound Import Table",
            L"Import Address Table",
            L"Delay Import Descriptor",
            L"CLI Runtime Header",
            L"Reserved"
        };

    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    const auto &dir{peinfo.data_directory()};
    for (size_t i = 0; i < dir.size(); ++i)
    {
        lvi.iItem = static_cast<int>(i);    // the size of the data directory should never exceed max int
        lvi.iSubItem = 0;

        _tcscpy_s(text_buffer.data(), text_buffer.size(),
                    i < (sizeof(data_table_names) / sizeof(data_table_names[0]))
                        ? data_table_names[i] : L"???");
        insert_item(&lvi);
        lvi.iSubItem = 1;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", dir[i].virtual_address);
        set_item(&lvi);
        lvi.iSubItem = 2;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", dir[i].size);
        set_item(&lvi);

        const auto *section{find_section_by_rva(dir[i].virtual_address, peinfo.sections())};
        if (section)
        {
            // If the name occupies exactly eight bytes, it is not nul-terminated,
            // so we copy the name into a nul-terminated temporary buffer.
            auto &name{section->header().name};
            constexpr auto sz{sizeof(name) / sizeof(name[0])};
            char name_buffer[sz + 1]{0};
            std::copy(name, name + sz, name_buffer);

            MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, name_buffer, sizeof(name_buffer), text_buffer.data(), static_cast<int>(text_buffer.size()));
            lvi.iSubItem = 3;
            set_item(&lvi);
        }
    }
}

void MainList::populate_pe_section_headers(const PeExeInfo::SectionTable &section_table)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 100;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Virtual size");
    lvc.cx = 100;
    insert_column(1, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 2;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Virtual address");
    lvc.cx = 100;
    insert_column(2, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 3;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Raw data size");
    lvc.cx = 100;
    insert_column(3, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 4;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Raw data offset");
    lvc.cx = 100;
    insert_column(4, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 5;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Relocations offset");
    lvc.cx = 100;
    insert_column(5, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 6;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Line numbers offset");
    lvc.cx = 100;
    insert_column(6, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 7;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of relocations");
    lvc.cx = 100;
    insert_column(7, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 8;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of line numbers");
    lvc.cx = 100;
    insert_column(8, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 9;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Characteristics");
    lvc.cx = 100;
    insert_column(9, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 10;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Meaning");
    lvc.cx = 100;
    insert_column(10, &lvc);

    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    for (const auto &section : section_table)
    {
        // If the name occupies exactly eight bytes, it is not nul-terminated,
        // so we copy the name into a nul-terminated temporary buffer.
        auto &name{section.header().name};
        constexpr auto  sz{sizeof(name) / sizeof(name[0])};
        char name_buffer[sz + 1]{0};
        std::copy(name, name + sz, name_buffer);

        MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, name_buffer, sizeof(name_buffer), text_buffer.data(), static_cast<int>(text_buffer.size()));
        lvi.iSubItem = 0;
        insert_item(&lvi);

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", section.header().virtual_size);
        ++lvi.iSubItem;
        set_item(&lvi);

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", section.header().virtual_address);
        ++lvi.iSubItem;
        set_item(&lvi);

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", section.header().size_of_raw_data);
        ++lvi.iSubItem;
        set_item(&lvi);

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", section.header().raw_data_position);
        ++lvi.iSubItem;
        set_item(&lvi);

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", section.header().relocations_position);
        ++lvi.iSubItem;
        set_item(&lvi);

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", section.header().line_numbers_position);
        ++lvi.iSubItem;
        set_item(&lvi);

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", section.header().number_of_relocations);
        ++lvi.iSubItem;
        set_item(&lvi);

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", section.header().number_of_line_numbers);
        ++lvi.iSubItem;
        set_item(&lvi);

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", section.header().characteristics);
        ++lvi.iSubItem;
        set_item(&lvi);

        //TODO: Add characteristics values in last column!!!

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli(const PeCli &cli)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    lvc.fmt = LVCFMT_RIGHT;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Offset");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    ++lvc.iSubItem;
    lvc.fmt = LVCFMT_LEFT;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Section");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};
    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    lvi.iSubItem = 0;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%016I64X", cli.file_offset());
    insert_item(&lvi);

    ++lvi.iSubItem;
    // If the name occupies exactly eight bytes, it is not nul-terminated,
    // so we copy the name into a nul-terminated temporary buffer.
    auto &name{cli.section().header().name};
    constexpr auto  sz{sizeof(name) / sizeof(name[0])};
    char name_buffer[sz + 1] {0};
    //std::memcpy(name_buffer, name, sizeof(name));
    std::copy(name, name + sz, name_buffer);

    MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, name_buffer, sizeof(name_buffer), text_buffer.data(), static_cast<int>(text_buffer.size()));
    set_item(&lvi);
}

void MainList::populate_pe_cli_header(const PeCliHeader &header)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};
    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 100;
    insert_column(1, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 2;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Meaning");
    lvc.cx = 200;
    insert_column(2, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size in bytes");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.size);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Major runtime version");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.major_runtime_version);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Minor runtime version");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.minor_runtime_version);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Metadata RVA");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.metadata.virtual_address);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Metadata size");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.metadata.size);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.flags);
    set_item(&lvi);
    //TODO: expand flags into next-door sub-item!!!


    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Entry point token");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08x", header.size);
    set_item(&lvi);


    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Resources RVA");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.resources.virtual_address);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Resources size");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.resources.size);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Strong name signature RVA");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.strong_name_signature.virtual_address);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Strong name signature size");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.strong_name_signature.size);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Code manager table RVA");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.code_manager_table.virtual_address);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Code manager size");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.code_manager_table.size);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Vtable fixups RVA");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.vtable_fixups.virtual_address);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Vtable fixups size");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.vtable_fixups.size);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Export address table jumps RVA");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.export_address_table_jumps.virtual_address);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Export address table jumps size");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.export_address_table_jumps.size);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Managed native header RVA");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.managed_native_header.virtual_address);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Managed native header size");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.managed_native_header.size);
    set_item(&lvi);
}

void MainList::populate_pe_cli_metadata_header(const PeCliMetadataHeader &header)
{
    clear();

    std::array<wchar_t, 260>    text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 100;
    insert_column(1, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.signature);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Major version");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.major_version);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Minor version");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.minor_version);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Version string length");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.version_length);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Version string");
    insert_item(&lvi);
    ++lvi.iSubItem;
    //constexpr auto x = std::numeric_limits<int>::max() - 1;
    //if (header.version.size() < x)
    if (header.version.size() < static_cast<size_t>(std::numeric_limits<int>::max()) - 1)
    {
        //std::unique_ptr<TCHAR[]> uptr;
        std::wstring    wstr;
        TCHAR  *pbuf{text_buffer.data()};
        int     sz{static_cast<int>(text_buffer.size())};

        if (header.version.size() >= text_buffer.size())
        {
            wstr.resize(header.version.size() + 1);
            pbuf = wstr.data();
            lvi.pszText = pbuf;
            sz = static_cast<int>(header.version.size());
        }
        MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, header.version.c_str(), static_cast<int>(header.version.size() + 1), pbuf, sz);
        set_item(&lvi);
        lvi.pszText = text_buffer.data();
    }

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", header.flags);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number of streams");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", header.stream_count);
    set_item(&lvi);
}

void MainList::populate_pe_cli_stream_headers(const std::vector<PeCliStreamHeader> &headers)
{
    clear();

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();

    lvc.fmt = LVCFMT_LEFT;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Offset");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Size in bytes");
    lvc.cx = 100;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    for (auto &header : headers)
    {
        lvi.iSubItem = 0;
        {   // In case of a custom stream with a name length > 32 characters. Should never happen, but...

            std::string tmp_name{header.name};
            if (tmp_name != "#~" && tmp_name != "#Strings" && tmp_name != "#US" && tmp_name != "#GUID" && tmp_name != "#Blob")
                if (tmp_name.size() > 32)
                    tmp_name = "Invalid stream name--length > 32";
            MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, tmp_name.c_str(), static_cast<const int>(tmp_name.size() + 1), text_buffer.data(), static_cast<int>(text_buffer.size()));
            insert_item(&lvi);
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.offset);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", header.size);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

// Not quite sure what I thought this function was supposed to do...
void MainList::populate_pe_cli_stream_tables([[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
}

void MainList::populate_pe_cli_strings_stream(const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;


    std::array<wchar_t, 20> tmp_buf{0};
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = tmp_buf.data();
    lvc.fmt = LVCFMT_RIGHT;
    lvc.cx = 50;
    lvc.iSubItem = 0;
    _tcscpy_s(tmp_buf.data(), tmp_buf.size(), L"Index");
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.cx = 600;
    ++lvc.iSubItem;
    _tcscpy_s(tmp_buf.data(), tmp_buf.size(), L"String");
    insert_column(lvc.iSubItem, &lvc);

    int             cur_size{1024};     // Should be plenty for most cases
    std::wstring    text_buffer(cur_size, L'\0');
    auto            strings{metadata.get_strings_heap_strings()};
    uint32_t        ndx{0};
    LVITEM          lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;

    for (auto &s : strings)
    {
        lvi.iSubItem = 0;
        StringCbPrintf(text_buffer.data(), cur_size, L"%u", ndx);
        insert_item(&lvi);

        ++ndx;
        ++lvi.iSubItem;
        if (s.size() < static_cast<size_t>(std::numeric_limits<int>::max()) - 1)
        {
            if (text_buffer.size() <= s.size())
            {
                text_buffer.resize(s.size() + 1);
                cur_size = static_cast<int>(text_buffer.size());
                lvi.pszText = text_buffer.data();
            }
            MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, s.c_str(), static_cast<int>(s.size() + 1), text_buffer.data(), cur_size);
            set_item(&lvi);
        }

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_us_stream(const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;


    std::array<wchar_t, 80> tmp_buf{0};
    LVCOLUMN                lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = tmp_buf.data();
    lvc.fmt = LVCFMT_RIGHT;
    lvc.cx = 50;
    lvc.iSubItem = 0;
    _tcscpy_s(tmp_buf.data(), tmp_buf.size(), L"Index");
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.cx = 600;
    ++lvc.iSubItem;
    _tcscpy_s(tmp_buf.data(), tmp_buf.size(), L"User String");
    insert_column(lvc.iSubItem, &lvc);

    std::wstring    text_buffer(1024, L'\0');
    auto            strings{metadata.get_us_heap_strings()};
    uint32_t        ndx{0};
    LVITEM          lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;

    for (auto &s : strings)
    {
        lvi.iSubItem = 0;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++ndx;
        if (text_buffer.size() <= s.size())
        {
            text_buffer.resize(s.size() + 1);
            lvi.pszText = text_buffer.data();
        }
        // This code is likely to work ONLY on Windows. In Windows, wchar_t
        // is two bytes, for "Unicode" characters. On other systems, wchar_t
        // may be a different size (e.g., 4 bytes on Linux).
        _tcscpy_s(text_buffer.data(), text_buffer.size(), reinterpret_cast<const wchar_t *>(s.c_str()));

        ++lvi.iSubItem;
        set_item(&lvi);
        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_guid_stream(const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;


    std::array<wchar_t, 80> text_buffer{0};
    LVCOLUMN                lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();
    lvc.fmt = LVCFMT_RIGHT;
    lvc.cx = 50;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Index");
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.cx = 200;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"GUID");
    insert_column(lvc.iSubItem, &lvc);

    auto        guids{metadata.get_guid_heap_guids()};
    uint32_t    ndx{1};
    LVITEM      lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;

    for (auto &guid : guids)
    {
        lvi.iSubItem = 0;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++ndx;
        guid_to_string(guid, text_buffer.data(), text_buffer.size());

        ++lvi.iSubItem;
        set_item(&lvi);
        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_blob_stream(const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;


    std::wstring    text_buffer(1024, L'\0');
    LVCOLUMN        lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.pszText = text_buffer.data();
    lvc.fmt = LVCFMT_RIGHT;
    lvc.cx = 50;
    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Index");
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.cx = 50;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Length");
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    lvc.cx = 600;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    insert_column(lvc.iSubItem, &lvc);


    constexpr wchar_t   digits[] {L'0', L'1', L'2', L'3', L'4', L'5', L'6', L'7', L'8', L'9', L'A', L'B', L'C', L'D', L'E', L'F'};

    auto        blobs{metadata.get_blob_heap_blobs()};
    uint32_t    ndx{0};
    LVITEM      lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.iItem = 0;

    for (auto &blob : blobs)
    {
        lvi.iSubItem = 0;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);
        ++ndx;

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%I64u", blob.size());
        set_item(&lvi);

        if (text_buffer.size() <= blob.size() * 3)
        {
            text_buffer.resize(blob.size() * 3 + 1);
            lvi.pszText = text_buffer.data();
        }

        const size_t    len{blob.size()};
        uint8_t        *p_byte{blob.data()};
        uint8_t         nibble{};
        wchar_t        *p_text{text_buffer.data()};

        for (size_t i = 0; i < len; ++i)
        {
            nibble = ((*p_byte) >> 4) & 0x0F;
            *p_text++ = digits[nibble];
            nibble = (*p_byte) & 0x0F;
            *p_text++ = digits[nibble];
            *p_text++ = L'-';
            ++p_byte;
        }
        if (len)
            --p_text;   // back up over the last '-'
        *p_text = L'\0';

        ++lvi.iSubItem;
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_tables(const PeCliMetadataTablesStreamHeader &header)
{
    clear();

    std::array<wchar_t, 20> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Item");
    lvc.cx = 200;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    lvc.iSubItem = 1;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value");
    lvc.cx = 150;
    insert_column(1, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"reserved");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", header.reserved0);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Major version");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hhu", header.major_version);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Minor version");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hhu", header.minor_version);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Heap sizes");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%02hhX", header.heap_sizes);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"reserved");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%02hhX", header.reserved1);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Valid tables");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%016I64X", header.valid_tables);
    set_item(&lvi);

    ++lvi.iItem;
    lvi.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Sorted tables");
    insert_item(&lvi);
    ++lvi.iSubItem;
    StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%016I64X", header.sorted_tables);
    set_item(&lvi);
}

namespace {
std::wstring get_wide_string(const PeCliMetadata &metadata, uint32_t index)
{
#if 0
    std::string str{metadata.get_string(index)};

    if (str.size() < static_cast<size_t>(std::numeric_limits<int>::max()) - 1)
    {
        std::wstring    wide_str(str.size() + 1, L'\0');
        MultiByteToWideChar(CP_UTF8, MB_PRECOMPOSED, str.c_str(), static_cast<int>(str.size() + 1), wide_str.data(), static_cast<int>(wide_str.size()));

        return wide_str;
    }

    return {};  // Empty string could be legit, or (FAR less likely) the retrieved narrow string contains > 2 billion characters.
#else
    return make_wide(metadata.get_string(index)).value_or(L"");
#endif
}

inline uint32_t make_token(PeCliMetadataTableId id, uint32_t index) noexcept
{
    return index | (static_cast<uint32_t>(id) << 24);
}
inline uint32_t make_token(const PeCliMetadataTableIndex &index) noexcept
{
    return make_token(index.table_id, index.index);
}

}   // anonymous namespace

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowAssembly> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Hash Algorthm");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Version");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Public Key Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 200;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Culture");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Assembly, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04x", row.hash_alg_id);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu.%hu.%hu.%hu", row.major_version, row.minor_version, row.build_number, row.revision_number);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        if (row.public_key)
        {
            StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.public_key);
            set_item(&lvi);
        }

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        if (row.culture)
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyOS> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS Platform ID");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS Major Version");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS Minor Version");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::AssemblyOS, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08x", row.os_platformID);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.os_major_version);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.os_minor_version);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyProcessor> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Processor");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::AssemblyProcessor, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08x", row.processor);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyRef> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Version");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Public Key Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 200;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Culture");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Hash Value");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::AssemblyRef, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu.%hu.%hu.%hu", row.major_version, row.minor_version, row.build_number, row.revision_number);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        if (row.public_key_or_token)
        {
            StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.public_key_or_token);
            set_item(&lvi);
        }

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        if (row.culture)
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.hash_value);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyRefOS> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS Platform ID");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS Major Version");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"OS Minor Version");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"AssemblyRef Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::AssemblyRefOS, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08x", row.os_platformID);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.os_major_version);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.os_minor_version);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.assembly_ref);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowAssemblyRefProcessor> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Processor");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"AssemblyRef Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::AssemblyRefProcessor, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08x", row.processor);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.assembly_ref);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowClassLayout> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Packing Size");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Class Size");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Parent");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::ClassLayout, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", row.packing_size);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.class_size);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeDef, row.parent));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowConstant> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Type");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Parent");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Constant, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%02hhX", row.type);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::HasConstant, row.parent)));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.value);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowCustomAttribute> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Parent");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Type");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Value Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::CustomAttribute, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::HasCustomAttribute, row.parent)));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::CustomAttributeType, row.type)));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.value);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowDeclSecurity> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Action");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Parent");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Permission Set Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::DeclSecurity, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.action);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::HasDeclSecurity, row.parent)));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.permission_set);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowEvent> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Type");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Event, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.event_flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::TypeDefOrRef, row.event_type)));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowEventMap> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Parent");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Event List");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::EventMap, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeDef, row.parent));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Event, row.event_list));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowExportedType> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};


    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"TypeDef ID");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Namespace");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Implementation");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::ExportedType, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeDef, row.typedef_id));
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.type_name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        if (row.type_namespace)
        {
            auto wstr{get_wide_string(metadata, row.type_namespace)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::Implementation, row.implementation)));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowField> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Field, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.signature);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowFieldLayout> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Offset");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Field");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::FieldLayout, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.offset);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Field, row.field));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowFieldMarshal> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Parent");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Native Type Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::FieldMarshal, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::HasFieldMarshall, row.parent)));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.native_type);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowFieldRVA> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RVA");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Field");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::FieldRVA, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.rva);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Field, row.field));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowFile> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Hash Value Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::File, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.hash_value);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowGenericParam> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Number");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Owner");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::GenericParam, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", row.number);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::TypeOrMethodDef, row.owner)));
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowGenericParamConstraint> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Owner");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Constraint");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::GenericParamConstraint, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::GenericParam, row.owner));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::TypeDefOrRef, row.constraint)));
        set_item(&lvi);


        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowImplMap> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Mapping Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Member Forwarded");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Import Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Import Scope");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::ImplMap, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.mapping_flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::MemberForwarded, row.member_forwarded)));
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.import_name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::ModuleRef, row.import_scope));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowInterfaceImpl> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Class");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Interface");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::InterfaceImpl, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeDef, row.class_));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::TypeDefOrRef, row.interface_)));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowManifestResource> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Offset");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Implementation");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::ManifestResource, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.offset);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::Implementation, row.implementation)));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowMemberRef> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Class");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::MemberRef, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::MemberRefParent, row.class_)));
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.signature);
        set_item(&lvi);

        ++lvi.iItem;
    }
}


void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowMethodDef> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RVA");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"ImplFlags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Param List");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::MethodDef, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.rva);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.impl_flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.signature);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Param, row.param_list));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowMethodImpl> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Class");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Method Body");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Method Declaration");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::MethodImpl, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeDef, row.class_));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::MethodDefOrRef, row.method_body)));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::MethodDefOrRef, row.method_declaration)));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowMethodSemantics> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Semantics");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Method");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Association");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::MethodSemantics, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.semantics);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::MethodDef, row.method));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::HasSemantics, row.association)));
        set_item(&lvi);

        ++lvi.iItem;
    }
}


void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowMethodSpec> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Method");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Instantiation Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::MethodSpec, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::MethodDefOrRef, row.method)));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.instantiation);
        set_item(&lvi);


        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowModule> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Generation");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Mvid");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"EncId");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"EncBaseId");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Module, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%hu", row.generation);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        if (row.mv_id)
        {
            const Guid  guid{metadata.get_guid(row.mv_id)};

            guid_to_string(guid, text_buffer.data(), text_buffer.size());
            set_item(&lvi);
        }

        ++lvi.iSubItem;
        if (row.enc_id)
        {
            const Guid  guid{metadata.get_guid(row.enc_id)};

            guid_to_string(guid, text_buffer.data(), text_buffer.size());
            set_item(&lvi);
        }

        ++lvi.iSubItem;
        if (row.enc_base_id)
        {
            const Guid  guid{metadata.get_guid(row.enc_base_id)};

            guid_to_string(guid, text_buffer.data(), text_buffer.size());
            set_item(&lvi);
        }

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowModuleRef> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::ModuleRef, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iItem;
    }
}


void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowNestedClass> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Nested Class");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Enclosing Class");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::NestedClass, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeDef, row.nested_class));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeDef, row.enclosing_class));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowParam> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Sequence");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Param, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.sequence);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowProperty> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Type Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Property, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%04hX", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.type);
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowPropertyMap> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Parent");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Property List");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::PropertyMap, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeDef, row.parent));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Property, row.property_list));
        set_item(&lvi);

        ++lvi.iItem;
    }
}


void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowStandAloneSig> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::StandAloneSig, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.signature);
        set_item(&lvi);

        ++lvi.iItem;
    }
}


void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowTypeDef> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Flags");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Namespace");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Extends");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Field List");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Method List");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeDef, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", row.flags);
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.type_name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        if (row.type_namespace)
        {
            auto wstr{get_wide_string(metadata, row.type_namespace)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        //TODO: Examine these three. Sometimes seeing strange values.
        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::TypeDefOrRef, row.extends)));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::Field, row.field_list));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::MethodDef, row.method_list));
        set_item(&lvi);

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowTypeRef> &table, const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Resolution Scope");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Name");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_LEFT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Namespace");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeRef, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(metadata.decode_index(PeCliEncodedIndexType::ResolutionScope, row.resolution_scope)));
        set_item(&lvi);

        ++lvi.iSubItem;
        {
            auto wstr{get_wide_string(metadata, row.type_name)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iSubItem;
        if (row.type_namespace)
        {
            auto wstr{get_wide_string(metadata, row.type_namespace)};

            lvi.pszText = wstr.data();
            set_item(&lvi);
            lvi.pszText = text_buffer.data();
        }

        ++lvi.iItem;
    }
}

void MainList::populate_pe_cli_table(const std::vector<PeCliMetadataRowTypeSpec> &table, [[maybe_unused]]const PeCliMetadata &metadata)
{
    clear();
    WaitCursor  waiter;

    std::array<wchar_t, 80> text_buffer{0};

    // Add the column headers
    LVCOLUMN    lvc{};

    lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_TEXT | LVCF_SUBITEM;
    lvc.fmt = LVCFMT_LEFT;
    lvc.pszText = text_buffer.data();

    lvc.iSubItem = 0;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"RID");
    lvc.cx = 60;
    insert_column(0, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Token");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);

    lvc.fmt = LVCFMT_RIGHT;
    ++lvc.iSubItem;
    _tcscpy_s(text_buffer.data(), text_buffer.size(), L"Signature Index");
    lvc.cx = 150;
    insert_column(lvc.iSubItem, &lvc);


    // Insert the items
    LVITEM  lvi{};

    lvi.mask = LVIF_TEXT | LVIF_STATE;
    lvi.pszText = text_buffer.data();
    lvi.stateMask = 0;
    lvi.state = 0;

    lvi.iItem = 0;
    UINT32  ndx{1};
    for (auto &row : table)
    {
        lvi.iSubItem = 0;

        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", ndx);
        insert_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"0x%08X", make_token(PeCliMetadataTableId::TypeSpec, ndx++));
        set_item(&lvi);

        ++lvi.iSubItem;
        StringCbPrintf(text_buffer.data(), text_buffer.size(), L"%u", row.signature);
        set_item(&lvi);

        ++lvi.iItem;
    }
}
