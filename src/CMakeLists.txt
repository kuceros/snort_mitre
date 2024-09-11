include(CheckIncludeFileCXX)

add_subdirectory ( loggers )

include ( FindPkgConfig )
pkg_search_module ( SNORT3 REQUIRED snort>=3 )

