#include <fstream>
#include <memory>

#include <tchar.h>

//#include "pch.h"    // pre-compiled headers
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#if defined(min)
#undef min
#endif
#if defined(max)
#undef max
#endif

#include "MainWindow.h"

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE, _In_ PWSTR lpCmdLine, _In_ int nCmdShow)
{
    INITCOMMONCONTROLSEX cc{sizeof(INITCOMMONCONTROLSEX), ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_TAB_CLASSES};
    InitCommonControlsEx(&cc);

    MainWindow::Register(hInstance);

    MainWindow  win;
    if (!win.Create(L"ExeXamine"))
        return -1;

    if (_tcsclen(lpCmdLine))
        win.load_file(lpCmdLine);

    ShowWindow(win.handle(), nCmdShow);

    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return static_cast<int>(msg.wParam);
}
