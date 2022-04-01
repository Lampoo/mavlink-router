# Cmake find modules
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_LIST_DIR}/cmake")

include(CheckCXXCompilerFlag)
include(CheckCXXSourceCompiles)
include(CheckCXXSymbolExists)
include(CheckIncludeFileCXX)
include(CheckStructHasMember)

# check if _GNU_SOURCE is available
if(NOT _GNU_SOURCE)
    check_cxx_symbol_exists(__GNU_LIBRARY__ "features.h" _GNU_SOURCE)
    if(NOT _GNU_SOURCE)
        unset(_GNU_SOURCE CACHE)
        check_cxx_symbol_exists(_GNU_SOURCE "features.h" _GNU_SOURCE)
    endif()
endif()
if(_GNU_SOURCE)
    add_definitions(-D_GNU_SOURCE)
endif()

find_package(rt)
if(rt_FOUND)
    set(CMAKE_REQUIRED_LIBRARIES ${rt_LIBRARIES})
endif()

check_include_file_cxx("aio.h" HAVE_AIO_H)
if(${HAVE_AIO_H})
    add_definitions(-DHAVE_AIO_H=1)
endif()
check_cxx_symbol_exists(aio_init "aio.h" HAVE_DECL_AIO_INIT)
if(${HAVE_DECL_AIO_INIT})
    add_definitions(-DHAVE_DECL_AIO_INIT=1)
endif()

function(add_cxx_compiler_flags var)
    foreach(flag ${ARGN})
        string(REGEX REPLACE "[^a-zA-Z0-9]+" "_" flag_var "CXXFLAG_${flag}")
        check_cxx_compiler_flag("${flag}" ${flag_var})
        if(${flag_var})
            set(${var} "${${var}} ${flag}")
            set(${flag_var} ${${flag_var}} PARENT_SCOPE)
            #message("bool ${flag_var}")
        endif()
    endforeach()
    set(${var} "${${var}}" PARENT_SCOPE)
endfunction()

set(MAVLINK_ROUTER_EXTRA_CXX_FLAGS
    -Waddress-of-packed-member -Wno-inline -Wundef -Wformat=2 -Wlogical-op -Wsign-compare
    -Wformat-security -Wmissing-include-dirs -Wformat-nonliteral -Wpointer-arith -Winit-self
    -Wfloat-equal -Wredundant-decls -Wmissing-declarations -Wmissing-noreturn -Wshadow
    -Wendif-labels -Wstrict-aliasing=3 -Wwrite-strings -Wno-long-long -Wno-overlength-strings
    -Wno-unused-parameter -Wno-missing-field-initializers -Wno-unused-result -Wchar-subscripts
    -Wtype-limits -Wuninitialized -Wno-implicit-fallthrough
    )

add_cxx_compiler_flags(CMAKE_CXX_FLAGS -Wall -pedentic -Wextra ${MAVLINK_ROUTER_EXTRA_CXX_FLAGS})

if(${CXXFLAG_Waddress_of_packed_member})
    add_definitions(-DHAVE_WADDRESS_OF_PACKED_MEMBER=1)
endif()

include_directories(
    modules/mavlink_c_library_v2/ardupilotmega
    src
    )

add_subdirectory(src)
