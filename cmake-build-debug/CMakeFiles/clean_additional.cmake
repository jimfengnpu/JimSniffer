# Additional clean files
cmake_minimum_required(VERSION 3.16)

if("${CONFIG}" STREQUAL "" OR "${CONFIG}" STREQUAL "Debug")
  file(REMOVE_RECURSE
  "CMakeFiles/JimSniffer_autogen.dir/AutogenUsed.txt"
  "CMakeFiles/JimSniffer_autogen.dir/ParseCache.txt"
  "JimSniffer_autogen"
  )
endif()
