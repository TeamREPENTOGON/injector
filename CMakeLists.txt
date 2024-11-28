cmake_minimum_required (VERSION 3.13.0)

project (Injector C)

set (CMAKE_C_STANDARD 11)

add_library (injector STATIC src/injector.c src/loader.c src/error.c
  include/injector/injector.h include/injector/private/loader.h include/injector/error.h
  include/injector/private/error.h)
add_compile_definitions (injector PUBLIC _CRT_SECURE_NO_WARNINGS)
target_include_directories (injector PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries (injector ImageHlp)

add_executable (test_injector src/tests/injector.c)
target_include_directories (test_injector PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries (test_injector injector)

add_library (injected_lib SHARED src/tests/injected_lib.c)

add_executable (injected src/tests/injected_executable.c)
