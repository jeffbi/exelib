
add_executable(fntextract)

target_sources(fntextract
    PRIVATE
        fntextract.cpp
)

target_compile_features(fntextract PUBLIC cxx_std_14)
target_link_libraries(fntextract PRIVATE exelib)
