# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.29

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/local/Cellar/cmake/3.29.0/bin/cmake

# The command to remove a file.
RM = /usr/local/Cellar/cmake/3.29.0/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /Users/kucera.rosta/desktop/snort3_extra

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /Users/kucera.rosta/desktop/snort3_extra/build

# Include any dependencies generated for this target.
include src/tp_appid/CMakeFiles/tp_appid_example.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include src/tp_appid/CMakeFiles/tp_appid_example.dir/compiler_depend.make

# Include the progress variables for this target.
include src/tp_appid/CMakeFiles/tp_appid_example.dir/progress.make

# Include the compile flags for this target's objects.
include src/tp_appid/CMakeFiles/tp_appid_example.dir/flags.make

src/tp_appid/CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.o: src/tp_appid/CMakeFiles/tp_appid_example.dir/flags.make
src/tp_appid/CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.o: /Users/kucera.rosta/desktop/snort3_extra/src/tp_appid/tp_appid_example.cc
src/tp_appid/CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.o: src/tp_appid/CMakeFiles/tp_appid_example.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --progress-dir=/Users/kucera.rosta/desktop/snort3_extra/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object src/tp_appid/CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.o"
	cd /Users/kucera.rosta/desktop/snort3_extra/build/src/tp_appid && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT src/tp_appid/CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.o -MF CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.o.d -o CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.o -c /Users/kucera.rosta/desktop/snort3_extra/src/tp_appid/tp_appid_example.cc

src/tp_appid/CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Preprocessing CXX source to CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.i"
	cd /Users/kucera.rosta/desktop/snort3_extra/build/src/tp_appid && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /Users/kucera.rosta/desktop/snort3_extra/src/tp_appid/tp_appid_example.cc > CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.i

src/tp_appid/CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green "Compiling CXX source to assembly CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.s"
	cd /Users/kucera.rosta/desktop/snort3_extra/build/src/tp_appid && /Library/Developer/CommandLineTools/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /Users/kucera.rosta/desktop/snort3_extra/src/tp_appid/tp_appid_example.cc -o CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.s

# Object files for target tp_appid_example
tp_appid_example_OBJECTS = \
"CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.o"

# External object files for target tp_appid_example
tp_appid_example_EXTERNAL_OBJECTS =

src/tp_appid/tp_appid_example.so: src/tp_appid/CMakeFiles/tp_appid_example.dir/tp_appid_example.cc.o
src/tp_appid/tp_appid_example.so: src/tp_appid/CMakeFiles/tp_appid_example.dir/build.make
src/tp_appid/tp_appid_example.so: src/tp_appid/CMakeFiles/tp_appid_example.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color "--switch=$(COLOR)" --green --bold --progress-dir=/Users/kucera.rosta/desktop/snort3_extra/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX shared module tp_appid_example.so"
	cd /Users/kucera.rosta/desktop/snort3_extra/build/src/tp_appid && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/tp_appid_example.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
src/tp_appid/CMakeFiles/tp_appid_example.dir/build: src/tp_appid/tp_appid_example.so
.PHONY : src/tp_appid/CMakeFiles/tp_appid_example.dir/build

src/tp_appid/CMakeFiles/tp_appid_example.dir/clean:
	cd /Users/kucera.rosta/desktop/snort3_extra/build/src/tp_appid && $(CMAKE_COMMAND) -P CMakeFiles/tp_appid_example.dir/cmake_clean.cmake
.PHONY : src/tp_appid/CMakeFiles/tp_appid_example.dir/clean

src/tp_appid/CMakeFiles/tp_appid_example.dir/depend:
	cd /Users/kucera.rosta/desktop/snort3_extra/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /Users/kucera.rosta/desktop/snort3_extra /Users/kucera.rosta/desktop/snort3_extra/src/tp_appid /Users/kucera.rosta/desktop/snort3_extra/build /Users/kucera.rosta/desktop/snort3_extra/build/src/tp_appid /Users/kucera.rosta/desktop/snort3_extra/build/src/tp_appid/CMakeFiles/tp_appid_example.dir/DependInfo.cmake "--color=$(COLOR)"
.PHONY : src/tp_appid/CMakeFiles/tp_appid_example.dir/depend
