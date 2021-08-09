cmake_minimum_required(VERSION 3.13)

project(exelib LANGUAGES CXX)

set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_subdirectory(exelib)
add_subdirectory(samples/exedump)
add_subdirectory(samples/fntextract)
