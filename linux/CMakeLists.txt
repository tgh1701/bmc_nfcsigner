# The Flutter tooling requires that developers have CMake 3.10 or later
# installed. You should not increase this version, as doing so will cause
# the plugin to fail to compile for some customers of the plugin.
cmake_minimum_required(VERSION 3.10)

# Project-level configuration.
set(PROJECT_NAME "nfcsigner")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed.
set(PLUGIN_NAME "nfcsigner_plugin")

# Find required packages for Linux
find_package(PkgConfig REQUIRED)

# Find PC/SC Lite
pkg_check_modules(PCSC REQUIRED libpcsclite)
if(PCSC_FOUND)
    message(STATUS "Found PC/SC Lite: ${PCSC_INCLUDE_DIRS}")
    add_compile_definitions(HAVE_PCSC=1)
endif()

# Find OpenSSL
find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    message(STATUS "Found OpenSSL: ${OPENSSL_INCLUDE_DIR}")
endif()

# Find PoDoFo
# Cách 1: Tìm qua pkg-config
pkg_check_modules(PODOFO_PKGCONFIG QUIET libpodofo)
if(PODOFO_PKGCONFIG_FOUND)
    message(STATUS "Found PoDoFo via pkg-config: ${PODOFO_PKGCONFIG_VERSION}")
    set(PODOFO_INCLUDE_DIRS ${PODOFO_PKGCONFIG_INCLUDE_DIRS})
    set(PODOFO_LIBRARIES ${PODOFO_PKGCONFIG_LIBRARIES})
    set(HAVE_PODOFO 1)
else()
    # Cách 2: Tìm thủ công các vị trí phổ biến trên Ubuntu
    find_path(PODOFO_INCLUDE_DIR
            NAMES podofo/podofo.h
            PATHS /usr/include
            /usr/local/include
            /usr/include/podofo
            NO_DEFAULT_PATH
    )

    find_library(PODOFO_LIBRARY
            NAMES podofo libpodofo
            PATHS /usr/lib/x86_64-linux-gnu
            /usr/lib
            /usr/local/lib
            NO_DEFAULT_PATH
    )

    if(PODOFO_INCLUDE_DIR AND PODOFO_LIBRARY)
        message(STATUS "Found PoDoFo manually:")
        message(STATUS "  Include: ${PODOFO_INCLUDE_DIR}")
        message(STATUS "  Library: ${PODOFO_LIBRARY}")
        set(PODOFO_INCLUDE_DIRS ${PODOFO_INCLUDE_DIR})
        set(PODOFO_LIBRARIES ${PODOFO_LIBRARY})
        set(HAVE_PODOFO 1)
    else()
        message(WARNING "PoDoFo not found - PDF signing will be disabled")
    endif()
endif()
if(PODOFO_FOUND)
    message(STATUS "Found PoDoFo: ${PODOFO_INCLUDE_DIRS}")
    add_compile_definitions(HAVE_PODOFO=1)

    # Additional PoDoFo dependencies that might be needed
    find_package(Fontconfig)
    find_package(FREETYPE)
    find_package(JPEG)
    find_package(PNG)
    find_package(TIFF)
else()
    message(WARNING "PoDoFo not found - PDF signing will be disabled")
    add_compile_definitions(HAVE_PODOFO=0)
endif()

# Any new source files that you add to the plugin should be added here.
list(APPEND PLUGIN_SOURCES
        "nfcsigner_plugin.cc"
        "nfcsigner_plugin_register.cpp"
)

# Define the plugin library target. Its name must not be changed (see comment
# on PLUGIN_NAME above).
add_library(${PLUGIN_NAME} SHARED
  ${PLUGIN_SOURCES}
)

# Apply a standard set of build settings that are configured in the
# application-level CMakeLists.txt. This can be removed for plugins that want
# full control over build settings.
apply_standard_settings(${PLUGIN_NAME})

# Symbols are hidden by default to reduce the chance of accidental conflicts
# between plugins. This should not be removed; any symbols that should be
# exported should be explicitly exported with the FLUTTER_PLUGIN_EXPORT macro.
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

# Source include directories and library dependencies. Add any plugin-specific
# dependencies here.
target_include_directories(${PLUGIN_NAME} INTERFACE
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        ${PCSC_INCLUDE_DIRS}
        ${PODOFO_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
)
target_link_libraries(${PLUGIN_NAME} PRIVATE
        flutter
        ${PCSC_LIBRARIES}
        ${PODOFO_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::GTK)

# List of absolute paths to libraries that should be bundled with the plugin.
# This list could contain prebuilt libraries, or libraries created by an
# external build triggered from this build file.
set(nfcsigner_bundled_libraries
  ""
  PARENT_SCOPE
)

# === Tests ===
# These unit tests can be run from a terminal after building the example.

# Only enable test builds when building the example (which sets this variable)
# so that plugin clients aren't building the tests.
#if (${include_${PROJECT_NAME}_tests})
#if(${CMAKE_VERSION} VERSION_LESS "3.11.0")
#message("Unit tests require CMake 3.11.0 or later")
#else()
#set(TEST_RUNNER "${PROJECT_NAME}_test")
#enable_testing()

# Add the Google Test dependency.
#include(FetchContent)
#FetchContent_Declare(
#  googletest
#  URL https://github.com/google/googletest/archive/release-1.11.0.zip
#)
# Prevent overriding the parent project's compiler/linker settings
#set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
# Disable install commands for gtest so it doesn't end up in the bundle.
#set(INSTALL_GTEST OFF CACHE BOOL "Disable installation of googletest" FORCE)

#FetchContent_MakeAvailable(googletest)

# The plugin's exported API is not very useful for unit testing, so build the
# sources directly into the test binary rather than using the shared library.
#add_executable(${TEST_RUNNER}
#  test/nfcsigner_plugin_test.cc
#  ${PLUGIN_SOURCES}
#)
#apply_standard_settings(${TEST_RUNNER})
#target_include_directories(${TEST_RUNNER} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
#target_link_libraries(${TEST_RUNNER} PRIVATE flutter)
#target_link_libraries(${TEST_RUNNER} PRIVATE PkgConfig::GTK)
#target_link_libraries(${TEST_RUNNER} PRIVATE gtest_main gmock)

# Enable automatic test discovery.
#include(GoogleTest)
#gtest_discover_tests(${TEST_RUNNER})

endif()  # CMake version check
endif()  # include_${PROJECT_NAME}_tests