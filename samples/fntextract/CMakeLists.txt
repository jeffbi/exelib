
add_executable(fntextract)

target_sources(fntextract
    PRIVATE
        fntextract.cpp
)

target_compile_features(fntextract PUBLIC cxx_std_14)
target_compile_options(fntextract PRIVATE
     $<$<OR:$<CXX_COMPILER_ID:Clang>,$<CXX_COMPILER_ID:AppleClang>,$<CXX_COMPILER_ID:GNU>>:
          -Wall>
     $<$<CXX_COMPILER_ID:MSVC>:
          /W4>)
target_link_libraries(fntextract PRIVATE exelib)
