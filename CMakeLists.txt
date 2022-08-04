cmake_minimum_required(VERSION 3.17)
project(detector)

set(CMAKE_CXX_STANDARD 14)

if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
  if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "4.9")
    message(FATAL_ERROR "Insufficient gcc version")
  endif()
endif()

add_executable(detector_pp main_pp.cpp)
add_executable(detector_flush main_flush.cpp)
