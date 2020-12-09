cmake_minimum_required(VERSION 3.12)

project(blink CXX)

set(SRCS
  source/blink.cpp
  source/blink.hpp
  source/blink_linker.cpp
  source/coff_reader.cpp
  source/coff_reader.hpp
  source/main.cpp
  source/scoped_handle.hpp
)
set(SRCS_PDB
  source/msf_reader.cpp
  source/msf_reader.hpp
  source/pdb_reader.cpp
  source/pdb_reader.hpp
)

set(CMAKE_CXX_STANDARD 17)

source_group("" FILES ${SRCS})
source_group("pdb" FILES ${SRCS_PDB})

add_executable(blink ${SRCS} ${SRCS_PDB})

if(MSVC)
  target_compile_options(blink PRIVATE
    /GS- # Disable Security Check
    /Gy  # Enable Function-Level Linking
  )
endif()

target_compile_definitions(blink PUBLIC
  NOMINMAX
)
