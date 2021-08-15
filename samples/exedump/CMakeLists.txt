
add_executable(exedump)

target_sources(exedump
    PRIVATE
        exedump.cpp
        nedump.cpp
        pedump.cpp
        HexVal.h
)

target_compile_features(exedump PUBLIC cxx_std_17)
target_link_libraries(exedump PRIVATE exelib)
