cmake_minimum_required(VERSION 3.6)
project(sdk)

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ../bin)

# C99 BOIIIIIIIIIIIIIIIIIIIIII
set(CMAKE_C_STANDARD 99)

# Use mingw x86 for windows compile
set(CMAKE_FIND_ROOT_PATH  /usr/bin/)

set(CMAKE_AR /usr/bin/i686-w64-mingw32-ar CACHE FILEPATH "Ar" FORCE)
set(CMAKE_RANLIB /usr/bin/i686-w64-mingw32-ranlib CACHE FILEPATH "Ranlib" FORCE)
set(CMAKE_C_COMPILER i686-w64-mingw32-gcc)


set(SOURCE_FILES
        src/api/api.c
        src/api/api.h
        src/api/kernel.c
        src/api/pe.h
        src/api/string.c
        src/sdk.c
        src/sdk.h
        src/main.c)

add_library(sdk STATIC ${SOURCE_FILES})