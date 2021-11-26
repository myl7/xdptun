cmake_minimum_required(VERSION 3.0)
project(xdptun C)

set(CMAKE_C_STANDARD 99)
include_directories(include)

add_executable(uot EXCLUDE_FROM_ALL src/uot.c include/mem.h include/log.h)
