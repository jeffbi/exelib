
add_executable(exedump)

target_sources(exedump
    PRIVATE
        exedump.cpp
        nedump.cpp
        pedump.cpp
)

target_compile_features(exedump PUBLIC cxx_std_20)
target_link_libraries(exedump PRIVATE exelib)
