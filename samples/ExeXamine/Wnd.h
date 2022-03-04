#ifndef _WND_H_
#define _WND_H_

class Window
{
public:
    Window() noexcept
        : _hwnd{nullptr}
    {}

    Window(const Window &) = delete;
    Window(const Window &&) = delete;
    Window &operator=(const Window &) = delete;
    Window &operator=(Window &&) = delete;

    virtual ~Window()
    {}

    /*virtual*/ bool Create(LPCTSTR class_name,
                        LPCTSTR window_name,
                        DWORD style,
                        DWORD ex_style = 0,
                        int x = CW_USEDEFAULT,
                        int y = CW_USEDEFAULT,
                        int width = CW_USEDEFAULT,
                        int height = CW_USEDEFAULT,
                        HWND parent = nullptr,
                        HMENU menu_or_id = nullptr,
                        LPVOID param = nullptr) noexcept
    {
        handle(CreateWindowEx(ex_style,
                              class_name,
                              window_name,
                              style,
                              x,
                              y,
                              width,
                              height,
                              parent,
                              menu_or_id,
                              GetModuleHandle(nullptr),
                              param));

        return handle() != nullptr;
    }

    /*virtual*/ bool Create(LPCTSTR class_name,
                        LPCTSTR window_name,
                        DWORD style,
                        DWORD ex_style,
                        const RECT &rect,
                        Window *parent,
                        UINT id,
                        LPVOID param = nullptr) noexcept
    {
        return Create(class_name,
                      window_name,
                      style,
                      ex_style,
                      rect.left,
                      rect.top,
                      rect.right - rect.left,
                      rect.bottom - rect.top,
                      parent ? parent->handle() : nullptr,
                      reinterpret_cast<HMENU>(static_cast<INT_PTR>(id)),
                      param);
    }

    bool move(int x, int y, int width, int height, bool paint) noexcept
    {
        return MoveWindow(handle(), x, y, width, height, paint ? TRUE : FALSE) != FALSE;
    }

    HWND handle() const noexcept
    {
        return _hwnd;
    }

    HWND set_focus() const noexcept
    {
        return SetFocus(handle());
    }

protected:
    void handle(HWND hwnd) noexcept
    {
        _hwnd = hwnd;
    }

private:
    HWND    _hwnd{nullptr};
};
#endif  // _WND_H_
