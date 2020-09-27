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


include_directories(${CMAKE_CURRENT_SOURCE_DIR}/..)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../lib)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../dns)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/${OS}/include)
add_definitions("-D_GNU_SOURCE")

add_library( # Sets the name of the library.
        event

        # Sets the library as a shared library.
        SHARED

        # Provides a relative path to your source file(s).
        buffer.c
        multi_socks_epoll_server.c
        event.c
        timer.c
        common.c
        base.c
        connect.c

        ${CMAKE_CURRENT_SOURCE_DIR}/../dns/c_dns.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../dns/c_dns_header.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../log.c)

add_library(
        event-static

        STATIC

        buffer.c
        multi_socks_epoll_server.c
        event.c
        timer.c
        common.c
        base.c
        connect.c

        ${CMAKE_CURRENT_SOURCE_DIR}/../dns/c_dns.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../dns/c_dns_header.c
        ${CMAKE_CURRENT_SOURCE_DIR}/../log.c
)

if (ANDROID)
    find_library(
            log-lib
            log
    )

    if (EVENT_SSL_DISABLE)

    else ()
        add_definitions("-DEVENT_SSL")
        message("use ssl")
    endif ()

    target_link_libraries( # Specifies the target library.
            event
            coll
            openssl::ssl
            openssl::crypto

            ${log-lib}
            )

    target_link_libraries(
            event-static
            coll

            ${log-lib}
    )
else ()
    message(EVENT_SSL_DISABLE="${EVENT_SSL_DISABLE}")
    if (EVENT_SSL_DISABLE)
        set(OPENSSL_SSL "")
        set(OPENSSL_CRYPTO "")
    else ()
        add_definitions("-DEVENT_SSL")
        message("use ssl")


        if (CMAKE_HOST_APPLE)
            find_library(
                    OPENSSL_SSL
                    libssl.a

                    /usr/local/opt/openssl@1.1/lib
            )

            find_library(
                    OPENSSL_CRYPTO
                    libcrypto.a

                    /usr/local/opt/openssl@1.1/lib
            )

            if (NOT ${OPENSSL_SSL} MATCHES /usr/local/opt/openssl@1.1/lib/libssl.a)
                find_library(
                        OPENSSL_SSL
                        libssl.a

                        ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/${OS}/lib/
                )

                find_library(
                        OPENSSL_CRYPTO
                        libcrypto.a

                        ${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/${OS}/lib/
                )
            endif ()
        endif ()

        message("OPENSSL_SSL: ${OPENSSL_SSL}")
        message("OPENSSL_CRYPTO: ${OPENSSL_CRYPTO}")
    endif ()

    target_link_libraries(
            event
            coll

            ${OPENSSL_SSL}
            ${OPENSSL_CRYPTO}
    )

    target_link_libraries(
            event-static
            coll-static

            ${OPENSSL_SSL}
            ${OPENSSL_CRYPTO}
            pthread
            dl
    )
    set(CMAKE_INSTALL_PREFIX ../dependencies/${OS})
    install(TARGETS event DESTINATION bin)
endif ()