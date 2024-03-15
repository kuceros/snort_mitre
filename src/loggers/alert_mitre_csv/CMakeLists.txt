cmake_minimum_required ( VERSION 3.4.3 )
project ( alert_mitre_csv CXX )

set (CMAKE_CXX_STANDARD 14)
set (CMAKE_CXX_STANDARD_REQUIRED ON)
set (CMAKE_CXX_EXTENSIONS OFF)

if ( APPLE )
    set ( CMAKE_MACOSX_RPATH OFF )
endif ( APPLE )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

add_library (
    alert_mitre_csv MODULE
    alert_mitre_csv.cc
)

if ( APPLE )
    set_target_properties (
        alert_mitre_csv
        PROPERTIES
            LINK_FLAGS "-undefined dynamic_lookup"
    )
endif ( APPLE )

set_target_properties (
    alert_mitre_csv
    PROPERTIES
        PREFIX ""
)

target_include_directories (
    alert_mitre_csv PUBLIC
    ${SNORT3_INCLUDE_DIRS}
)

install (
    TARGETS alert_mitre_csv
    LIBRARY
        DESTINATION "${LOGGER_INSTALL_PATH}"
)
