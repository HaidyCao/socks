project(ssl_socks)

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

if (ANDROID)
    find_library(
            log-lib

            log
    )
else ()
    add_definitions(-DSOCKS_SSL)
    include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../dependencies/${OS}/include)
    add_executable(
            ssl_socks_local

            ssl_socks_local.c
    )

    target_link_libraries(
            ssl_socks_local

            libsocks-static
    )

    add_executable(
            ssl_socks_server

            ssl_socks_server.c
    )

    target_include_directories(
            ssl_socks_server
            PRIVATE

            ../dependencies/${OS}/include
    )

    target_link_libraries(
            ssl_socks_server

            libsocks-static
    )

    set(log-lib "")
endif ()