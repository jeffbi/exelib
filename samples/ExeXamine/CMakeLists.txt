
add_executable(ExeXamine WIN32)

target_sources(ExeXamine
    PRIVATE
        FileInfo.h
        ListView.h
        main.cpp
        MainList.cpp
        MainList.h
        MainTree.h
        MainWindow.cpp
        MainWindow.h
        ExeXamine.rc
        Wnd.h
)

target_compile_features(ExeXamine PUBLIC cxx_std_17)
target_compile_definitions(ExeXamine PRIVATE UNICODE _UNICODE)
target_compile_options(ExeXamine PRIVATE
    $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:
        -Wall -Wextra>
    $<$<CXX_COMPILER_ID:MSVC>:
        /W4>)
target_link_libraries(ExeXamine PRIVATE Comctl32 exelib)
