# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.
project(socks)
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

add_subdirectory(lib)
add_subdirectory(event)
add_subdirectory(dns)
add_subdirectory(socks5)
add_subdirectory(tools)

add_dependencies(
        event

        coll
)

if (SOCKS5_CLIENT_ENABLE)
    add_dependencies(
            socks5_client

            event
    )
endif ()

if (ANDROID)
    if (MSL_ENABLE)
        add_dependencies(
                msl

                event
                coll
        )
    endif ()
else ()
    add_dependencies(
            socks

            event-static
    )

    add_dependencies(
            mss

            event-static
    )
endif ()