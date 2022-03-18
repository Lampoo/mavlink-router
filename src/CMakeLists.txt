set(module_name mavlink-routerd)

add_executable(${module_name}
    # common sources
    common/conf_file.cpp
    common/log.cpp
    common/util.cpp
    common/xtermios.cpp

    # mavlink-routerd sources
    main.cpp
    autolog.cpp
    binlog.cpp
    dedup.cpp
    endpoint.cpp
    git_version.cpp
    logendpoint.cpp
    main.cpp
    mainloop.cpp
    pollable.cpp
    timeout.cpp
    ulog.cpp
)

set_property(
    TARGET ${module_name}
    PROPERTY CXX_STANDARD 14
)

set_property(
    TARGET ${module_name}
    PROPERTY COMPILE_OPTIONS -fPIC
)

#target_compile_options(
#    ${module_name}
#    PRIVATE -Wno-c++11-narrowing
#)

target_link_libraries(
    ${module_name}
    rt
    pthread
)