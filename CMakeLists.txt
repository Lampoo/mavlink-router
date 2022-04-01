cmake_minimum_required(VERSION 3.12)

project(mavlink_router CXX)

# Debug build type as default
if (NOT CMAKE_BUILD_TYPE)
    message(STATUS "No build type selected, using DEBUG")
    set(CMAKE_BUILD_TYPE "DEBUG")
endif ()
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_SOURCE_DIR}/cmake)

set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN 1)

find_package(Git)

if (GIT_FOUND)
    execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --always --dirty=+
            WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
            OUTPUT_VARIABLE MAVLINK_ROUTER_VERSION_GIT_REVISION
            OUTPUT_STRIP_TRAILING_WHITESPACE)

    message(STATUS "Building in git revision ${MAVLINK_ROUTER_VERSION_GIT_REVISION}")
else()
    set(MAVLINK_ROUTER_VERSION_GIT_REVISION "n/a")
    message(STATUS "Executable git is missing, choosing default value for git revision")
endif()

string(TIMESTAMP MAVLINK_ROUTER_VERSION_BUILD_TIMESTAMP "%Y-%m-%dT%H:%M:%S.000000Z" UTC)
message(STATUS "Building in build timestamp ${MAVLINK_ROUTER_VERSION_BUILD_TIMESTAMP}")
# generate version.h
include_directories(${CMAKE_BINARY_DIR})
set(VCS_TAG ${MAVLINK_ROUTER_VERSION_GIT_REVISION})
configure_file("${CMAKE_SOURCE_DIR}/src/version.h.in" "${CMAKE_BINARY_DIR}/git_version.h" @ONLY)

# vendor-specific setup goes here
add_definitions(-DVERSION=\"${MAVLINK_ROUTER_VERSION_GIT_REVISION}\" -DPACKAGE=\"mavlink-router\")

include(mavlink-router.cmake)
