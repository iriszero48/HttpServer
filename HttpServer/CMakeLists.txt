cmake_minimum_required(VERSION 3.9)
project(HttpServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(CMAKE_VERBOSE_MAKEFILE ON)

aux_source_directory(. srcs)
add_executable(HttpServer ${srcs})
target_link_libraries(HttpServer tbb)
