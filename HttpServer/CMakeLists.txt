cmake_minimum_required(VERSION 3.9)
project(HttpServer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MSYS OR MINGW)
	SET(CMAKE_CXX_FLAGS "-static")
	SET(CMAKE_SHARED_LIBRARY_LINK_CXX_FLAGS "-static")
endif()

set(CMAKE_VERBOSE_MAKEFILE ON)

find_package(Threads REQUIRED)

aux_source_directory(. srcs)
add_executable(hs ${srcs})

if(MSYS OR MINGW)
	target_link_libraries(hs Threads::Threads ws2_32)
else()
	target_link_libraries(hs PUBLIC Threads::Threads)
endif()
