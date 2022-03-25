# Cmake find modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

# generate version.h
include_directories(${CMAKE_BINARY_DIR})
set(VCS_TAG ${MAVLINK_ROUTER_VERSION_GIT_REVISION})
configure_file("${CMAKE_SOURCE_DIR}/src/version.h.in" "${CMAKE_BINARY_DIR}/git_version.h" @ONLY)

# vendor-specific setup goes here
add_definitions(-DVERSION=\"${MAVLINK_ROUTER_VERSION_GIT_REVISION}\" -DPACKAGE=\"mavlink-router\")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -pedantic -Wextra -fPIC")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -fno-strict-aliasing -pedantic -Wextra -Wno-implicit-fallthrough -fPIC")
if (NOT ANDROID)
  set(CMAKE_C_FLAGS "${CMAKE_CXX_FLAGS} -lrt")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lrt")
endif()

include_directories(
    modules/mavlink_c_library_v2/ardupilotmega
    src
)

add_subdirectory(src)
