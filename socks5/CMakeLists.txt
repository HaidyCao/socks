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

message("OS = ${OS}; CMAKE_SOURCE_DIR = ${CMAKE_SOURCE_DIR}")

# if (ANDROID)
#         set(OS android)
# endif()
message("OS = ${OS}; CMAKE_SOURCE_DIR = ${CMAKE_SOURCE_DIR}")

include_directories(..)
include_directories(../lib)
include_directories(../dns)
include_directories(../event)
include_directories(../dependencies/${M_OS}/include)
include_directories(../dependencies/kcp-1.7)
add_definitions("-D_GNU_SOURCE")

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
    add_definitions("-DEVENT_LOG_DISABLED")
endif ()

# Searches for a specified prebuilt library and stores the path as a
# variable. Because CMake includes system libraries in the search path by
# default, you only need to specify the name of the public NDK library
# you want to add. CMake verifies that the library exists before
# completing its build.

if (SOCKS5_CLIENT_ENABLE)
    add_library(
            socks5_client

            SHARED

            ${CMAKE_CURRENT_SOURCE_DIR}/socks5_client.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/kcp-1.7/ikcp.c
    )
endif ()

add_library(
        socks5_client-static

        STATIC

        ${CMAKE_CURRENT_SOURCE_DIR}/socks5_client.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/kcp-1.7/ikcp.c
)

add_library(
        libsocks-static

        ${CMAKE_CURRENT_SOURCE_DIR}/socks5.c
        ${CMAKE_CURRENT_SOURCE_DIR}/socks5_client.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/kcp-1.7/ikcp.c
)

if (MSL_ENABLE)
    add_library(
            msl

            SHARED

            socks5.c
            msl.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/kcp-1.7/ikcp.c
            multi_socks.c)
endif ()

if (ANDROID)

else ()
    if ("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
        add_definitions("-O2")
    else ()
        add_definitions("-Wall -g")
    endif ()

    add_executable(
            mss

            ../lib/c_linked_list.c
            ../lib/c_hash_map.c
            ../lib/c_sparse_array.c
            ../lib/c_hex_utils.c
            ../lib/clib.c
            multi_socks.c
            ../args_parser.c

            mss.c
            mss_main.c
    )

    add_library(
            socks-static

            STATIC

            socks5.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/kcp-1.7/ikcp.c
    )
endif ()

if (ANDROID)
    find_library(
            log-lib

            log
    )

    if (SOCKS5_SSL_DISABLE)
        set(E_SSL "")
        set(E_CRYPTO "")
    else ()
        set(EVENT_SSL_DISABLE 0)
        add_definitions("-DSOCKS_SSL -DEVENT_SSL")
    endif ()
else ()
    add_executable(
            socks

            socks5_main.c
            ../args_parser.c

            socks5.c
            msl.c
            multi_socks.c
            ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/kcp-1.7/ikcp.c
    )

    if (SOCKS5_SSL_DISABLE)
        set(E_SSL "")
        set(E_CRYPTO "")
    else ()
        set(EVENT_SSL_DISABLE 0)
        add_definitions("-DSOCKS_SSL -DEVENT_SSL")
    endif ()

    target_link_libraries(
            socks-static

            event-static
    )

    target_link_libraries(
            socks

            event-static
    )

    target_link_libraries(
            mss

            event-static
    )

    set(log-lib "")
endif ()

if (MSL_ENABLE)
    target_link_libraries(
            msl
            event
            coll

            ${log-lib}
    )
endif ()

if (SOCKS5_CLIENT_ENABLE)
    target_link_libraries(
            socks5_client

            event
            ${log-lib}
    )
endif ()

target_link_libraries(
        socks5_client-static

        event-static
        ${log-lib}
)

target_link_libraries(
        libsocks-static

        event-static
        ${log-lib}
)