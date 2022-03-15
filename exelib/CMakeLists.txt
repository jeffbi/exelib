
add_library(exelib STATIC)

target_sources(exelib
    PRIVATE
        MZExe.cpp
        NEExe.cpp
        PEExe.cpp
        CLI.cpp
        readers.h
        resource_type.h
    PUBLIC
        LoadOptions.h
        ExeInfo.h
        MZExe.h
        NEExe.h
        PEExe.h
)

target_compile_features(exelib PUBLIC cxx_std_14)
target_compile_options(exelib PRIVATE
    $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:
        -Wall -Wextra>
    $<$<CXX_COMPILER_ID:MSVC>:
        /W4>)
target_include_directories(exelib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
IF (NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
    set_target_properties(exelib PROPERTIES OUTPUT_NAME "exe" PREFIX "lib")
ENDIF ()
