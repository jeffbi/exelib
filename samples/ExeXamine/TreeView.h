#ifndef _TREE_VIEW_H_
#define _TREE_VIEW_H_

//#include "pch.h"    // pre-compiled headers
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include "Wnd.h"


class TreeView : public Window
{
public:
    TreeView() = default;
    TreeView(const TreeView &) = delete;
    TreeView(TreeView &&) = delete;
    TreeView &operator=(const TreeView &) = delete;
    TreeView &operator=(TreeView &&) = delete;

    virtual bool Create(LPCTSTR window_name,
                DWORD style,
                const RECT &rect,
                Window *parent,
                UINT id) noexcept
    {
        return Window::Create(WC_TREEVIEW,
                              window_name,
                              style,
                              0,
                              rect,
                              parent,
                              id);
    }

    void delete_all() noexcept
    {
        TreeView_DeleteAllItems(handle());
    }

    void expand(const HTREEITEM hitem, UINT code) noexcept
    {
        TreeView_Expand(handle(), hitem, code);
    }

    void select(const HTREEITEM hitem, UINT code) noexcept
    {
        TreeView_Select(handle(), hitem, code);
    }

    void select_item(const HTREEITEM hitem) noexcept
    {
        TreeView_SelectItem(handle(), hitem);
    }
};

#endif  // _TREE_VIEW_H_
