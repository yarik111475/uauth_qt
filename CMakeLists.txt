cmake_minimum_required(VERSION 3.5)
set(PROJECT_NAME UAUTH)
set(GLOBAL_VERSION 1.0.0)
project(${PROJECT_NAME} LANGUAGES CXX)
configure_file(Version.h.in Version.h)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
add_definitions(-DQT_MESSAGELOGCONTEXT)

if(WIN32)
    add_definitions(-DWIN32_LEAN_AND_MEAN)
    add_definitions(-D_WIN32_WINNT=0x0601)
    if(MSVC)
        add_definitions(-D_CRT_SECURE_NO_WARNINGS)
    endif()
endif()

if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(OPENSSL_LIBRARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/win32/openssl-1.1.1/x32/lib)
        set(OPENSSL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/win32/openssl-1.1.1/x32/include)
        set(OpenSSL_SSL_LIB ${OPENSSL_LIBRARY_DIR}/libssl.lib)
        set(OpenSSL_Crypto_LIB ${OPENSSL_LIBRARY_DIR}/libcrypto.lib)
    endif()
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(OPENSSL_LIBRARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/win32/openssl-1.1.1/x64/lib)
        set(OPENSSL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/win32/openssl-1.1.1/x64/include)
        set(OpenSSL_SSL_LIB ${OPENSSL_LIBRARY_DIR}/libssl.lib)
        set(OpenSSL_Crypto_LIB ${OPENSSL_LIBRARY_DIR}/libcrypto.lib)
    endif()

    set(WIN_LINKER_LIBS
    )
endif()

if(UNIX AND NOT APPLE)
    set(OPENSSL_LIBRARY_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/linux/openssl-1.1.1/lib)
    set(OPENSSL_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/linux/openssl-1.1.1/include)
    set(OpenSSL_SSL_LIB ${OPENSSL_LIBRARY_DIR}/libssl.so.1.1)
    set(OpenSSL_Crypto_LIB ${OPENSSL_LIBRARY_DIR}/libcrypto.so.1.1)

    set(LINUX_LINKER_LIBS
    -static-libgcc
    -static-libstdc++
    -pthread
    )
endif()

#spdlog
set(SPDLOG_MASTER_PROJECT OFF)
set(SPDLOG_INSTALL OFF)
set(SPDLOG_BUILD_SHARED OFF)
set(SPDLOG_WCHAR_FILENAMES ON)

#postgresql
if(WIN32)
    if(CMAKE_SIZEOF_VOID_P EQUAL 4)
        set(PostgreSQL_LIBRARY_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/win32/pgsql/x32/lib)
        set(PostgreSQL_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/win32/pgsql/x32/include)
    endif()
    if(CMAKE_SIZEOF_VOID_P EQUAL 8)
        set(PostgreSQL_LIBRARY_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/win32/pgsql/x64/lib)
        set(PostgreSQL_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/win32/pgsql/x64/include)
    endif()
    set(PostgreSQL_LIB libpq.lib)
endif()
if(UNIX AND NOT APPLE)
    set(PostgreSQL_LIBRARY_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/linux/pgsql/lib)
    set(PostgreSQL_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/3rdparty/linux/pgsql/include)
    set(PostgreSQL_LIB libpq.so.5.15)
endif()

#rpath
SET(CMAKE_SKIP_BUILD_RPATH  FALSE)
SET(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
SET(CMAKE_INSTALL_RPATH "\$ORIGIN/../lib;\$ORIGIN/../lib64")

add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/uaShell)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/uaServer)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/uaRequester)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/uaTables)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/qthttp)
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/lib/3rdparty/spdlog-1.9.2)
