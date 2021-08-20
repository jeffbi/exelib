
add_library(exelib STATIC)

target_sources(exelib
    PRIVATE
        MZExe.cpp
        NEExe.cpp
        PEExe.cpp
        readstream.h
        resource_type.h
    PUBLIC
        LoadOptions.h
        ExeInfo.h
        MZExe.h
        NEExe.h
        PEExe.h
)

target_compile_features(exelib PUBLIC cxx_std_14)
target_include_directories(exelib INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})
