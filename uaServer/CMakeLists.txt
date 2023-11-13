cmake_minimum_required(VERSION 3.5)
set(PROJECT_NAME UASERVER)
set(TARGET_NAME uaServer)
project(${PROJECT_NAME} LANGUAGES CXX VERSION ${GLOBAL_VERSION})

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
    add_compile_options(/bigobj)
endif()

file(GLOB_RECURSE PROJECT_SOURCES CONFIGURE_DEPENDS
    "*.h"
    "*.cpp"
)

#qt packages
find_package(Qt5 COMPONENTS Sql REQUIRED)
find_package(Qt5 COMPONENTS Core REQUIRED)
find_package(Qt5 COMPONENTS Network REQUIRED)
find_package(Qt5 COMPONENTS WebSockets REQUIRED)

add_executable(${TARGET_NAME}
  ${PROJECT_SOURCES}
)

target_include_directories(${TARGET_NAME} PRIVATE
    ${OPENSSL_INCLUDE_DIR}
    ${PostgreSQL_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/../lib/qthttp/src
)

target_link_libraries(${TARGET_NAME}
    Qt5::Sql
    Qt5::Core
    Qt5::Network
    Qt5::WebSockets
    ${OpenSSL_SSL_LIB}
    ${OpenSSL_Crypto_LIB}
    ${WIN_LINKER_LIBS}
    ${LINUX_LINKER_LIBS}
    ${PostgreSQL_LIBRARY_DIRS}/${PostgreSQL_LIB}
    spdlog
)

install(TARGETS ${TARGET_NAME}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
