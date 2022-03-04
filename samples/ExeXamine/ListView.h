#ifndef _LIST_VIEW_H_
#define _LIST_VIEW_H_

//#include "pch.h"    // pre-compiled headers
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif
#include <CommCtrl.h>

#include "Wnd.h"

class ListView : public Window
{
public:
    ListView() = default;
    ListView(const ListView &) = delete;
    ListView(ListView &&) = delete;
    ListView &operator=(const ListView &) = delete;
    ListView &operator=(ListView &&) = delete;

    using Window::Create;

    virtual bool Create(LPCTSTR window_name,
                DWORD style,
                const RECT &rect,
                Window *parent,
                UINT id) noexcept
    {
        return Window::Create(WC_LISTVIEW,
                              window_name,
                              style,
                              0,
                              rect,
                              parent,
                              id);
    }

    void delete_all() noexcept
    {
        ListView_DeleteAllItems(handle());
    }

    int insert_column(int index, const LVCOLUMN *col) noexcept
    {
        return ListView_InsertColumn(handle(), index, col);
    }

    bool delete_column(int index) noexcept
    {
        return ListView_DeleteColumn(handle(), index) != FALSE;
    }

    int insert_item(const LVITEM *item) noexcept
    {
        return ListView_InsertItem(handle(), item);
    }

    bool set_item(const LVITEM *item) noexcept
    {
        return ListView_SetItem(handle(), item) != FALSE;
    }

    void set_extended_style(DWORD styles) noexcept
    {
        ListView_SetExtendedListViewStyle(handle(), styles);
    }
};

#endif  //_LIST_VIEW_H_
