# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

if (CMAKE_HOST_APPLE)
    set(OS darwin)
    set(M_OS darwin)
elseif (CMAKE_HOST_UNIX)
    set(OS linux)
    set(M_OS linux)
endif ()
if (DEFINED ANDROID_ABI)
    set(OS android)
endif ()
message("OS = ${OS}; CMAKE_SOURCE_DIR = ${CMAKE_SOURCE_DIR}; M_OS = ${M_OS}")

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    add_definitions("-DEVENT_LOG_DISABLED -O2")
    set(CMAKE_C_LDFLAGS "${CMAKE_C_LDFLAGS} -s")
    message("Release build")
else ()
    add_definitions("-Wall -g")

endif ()

add_definitions("-D_GNU_SOURCE")

if (CDNS_ENABLE)
    add_library( # Sets the name of the library.
            cdns

            # Sets the library as a shared library.
            SHARED

            # Provides a relative path to your source file(s).
            ../log.c
            ../lib/c_hex_utils.c

            c_dns.c
            c_dns_header.c)
endif ()

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.


if (ANDROID)
    find_library( # Sets the name of the path variable.
            log-lib

            log)
else ()
    set(log-lib "")
    include_directories(${CMAKE_SOURCE_DIR}/../event)
    add_executable(
            dns_test

            c_dns_test.c
            ../log.c
            ../lib/c_hex_utils.c
    )

    target_link_libraries(
            dns_test

            cdns
    )
endif ()

if (CDNS_ENABLE)
    target_link_libraries(
            cdns

            ${log-lib}
    )
endif ()