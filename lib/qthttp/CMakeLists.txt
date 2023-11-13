cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME qthttp)
set(TARGET_NAME QtHttp)
project(${PROJECT_NAME} LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_INCLUDE_CURRENT_DIR ON)

add_definitions(-DQT_WEBSOCKETS_LIB)
add_definitions(-DQT_BUILD_SSLSERVER_LIB)
add_definitions(-DQT_BUILD_HTTPSERVER_LIB)

file(GLOB_RECURSE PROJECT_SOURCES CONFIGURE_DEPENDS
    "*.h"
    "*.cpp"
)

find_package(Qt5 COMPONENTS Core REQUIRED)
find_package(Qt5 COMPONENTS Network REQUIRED)
find_package(Qt5 COMPONENTS WebSockets REQUIRED)

add_library(${TARGET_NAME} SHARED
    ${PROJECT_SOURCES}
)

target_include_directories(${TARGET_NAME} PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(${TARGET_NAME} PRIVATE
    Qt5::Core
    Qt5::Network
    Qt5::WebSockets
)

install(TARGETS ${TARGET_NAME}
    DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
