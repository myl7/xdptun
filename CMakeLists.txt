cmake_minimum_required(VERSION 3.0)
project(xdptun C)

set(CMAKE_C_STANDARD 99)
include_directories(include)

add_executable(uot src/uot.c include/mem.h)
