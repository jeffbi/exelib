
add_executable(exedump)

target_sources(exedump
    PRIVATE
        exedump.cpp
        nedump.cpp
        pedump.cpp
        HexVal.h
)

target_compile_features(exedump PUBLIC cxx_std_17)
target_compile_options(exedump PRIVATE
    $<$<CXX_COMPILER_ID:Clang,AppleClang,GNU>:
        -Wall -Wextra>
    $<$<CXX_COMPILER_ID:MSVC>:
        /W4>)
target_link_libraries(exedump PRIVATE exelib)
