cmake_minimum_required(VERSION 3.16)
project(i1d3util LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(i1d3util i1d3util.cpp)

# Prefer a CMake package (works well with vcpkg on Windows).
find_package(hidapi CONFIG QUIET)
if(TARGET hidapi::hidapi)
  target_link_libraries(i1d3util PRIVATE hidapi::hidapi)
  return()
endif()

# Fallback to pkg-config (typical on macOS/Linux).
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  pkg_check_modules(HIDAPI QUIET hidapi hidapi-hidraw hidapi-libusb)
  if(HIDAPI_FOUND)
    target_include_directories(i1d3util PRIVATE ${HIDAPI_INCLUDE_DIRS})
    target_link_directories(i1d3util PRIVATE ${HIDAPI_LIBRARY_DIRS})
    target_link_libraries(i1d3util PRIVATE ${HIDAPI_LIBRARIES})
    return()
  endif()
endif()

# Final fallback: manual include/library lookup.
find_path(HIDAPI_INCLUDE_DIR hidapi/hidapi.h)
find_library(HIDAPI_LIBRARY NAMES hidapi hidapi-hidraw hidapi-libusb)
if(HIDAPI_INCLUDE_DIR AND HIDAPI_LIBRARY)
  target_include_directories(i1d3util PRIVATE ${HIDAPI_INCLUDE_DIR})
  target_link_libraries(i1d3util PRIVATE ${HIDAPI_LIBRARY})
else()
  message(FATAL_ERROR "hidapi not found. Install hidapi (Linux package may be hidapi-hidraw or hidapi-libusb; use vcpkg on Windows).")
endif()
