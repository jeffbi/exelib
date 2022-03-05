#ifndef _MAIN_WINDOW_H_
#define _MAIN_WINDOW_H_

#include <memory>

#include <chrono>

#include <ExeInfo.h>

#include "FileInfo.h"
#include "MainList.h"
#include "MainTree.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

// Child window IDs
#define ID_TREEVIEW     2001
#define ID_LISTVIEW     2002


//class MainWindow : public MainWindowBase<MainWindow>
class MainWindow : public Window
{
private:
    static constexpr const wchar_t *class_name{L"ExeInstector Main"};

public:
    static ATOM Register(const HINSTANCE hInstance) noexcept
    {
        WNDCLASS    wc{};

        wc.lpfnWndProc  = WindowProc;
        wc.hInstance    = hInstance;
        wc.lpszClassName= class_name;
        wc.hCursor      = LoadCursor(NULL, IDC_ARROW);

        return RegisterClass(&wc);
    }

    MainWindow() = default;
    MainWindow(const MainWindow &) = delete;
    MainWindow(MainWindow &&) = delete;
    MainWindow &operator=(const MainWindow &) = delete;
    MainWindow &operator=(MainWindow &&) = delete;

    bool Create(LPCTSTR window_name,
                int x = CW_USEDEFAULT,
                int y = CW_USEDEFAULT,
                int width = CW_USEDEFAULT,
                int height = CW_USEDEFAULT) noexcept
    {
        return Window::Create(class_name,
                              window_name,
                              WS_OVERLAPPEDWINDOW,
                              0,
                              x,
                              y,
                              width,
                              height,
                              nullptr,
                              LoadMenu(nullptr, L"IDR_MAINMENU"),
                              this);
    }

    void load_file(LPCTSTR file_path);

private:
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

    LRESULT handle_message(UINT msg, WPARAM wParam, LPARAM lParam);

    void create_child_windows() noexcept;
    void clear_ui() noexcept;
    void reset_ui();
    void populate_tree();
    void set_file_info(LPCTSTR path);


    // WM_* message Handlers
    void on_command(WPARAM wParam, LPARAM lParam);
    int on_notify(WPARAM wParam, LPARAM lParam);
    void on_size(WPARAM sizing_type, int width, int height) noexcept;

    // Notification handlers
    void on_notify_tvn_sel_changed(const NMTREEVIEW *view);

    void on_file_open();

    // Instance data
    MainTree                    _main_tree;
    MainList                    _main_list;
    std::unique_ptr<ExeInfo>    _exe_info{nullptr};
    FileInfo                    _file_info;
};

#endif  // _MAIN_WINDOW_H_
