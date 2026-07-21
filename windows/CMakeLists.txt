# The Flutter tooling requires that developers have a version of Visual Studio
# installed that includes CMake 3.14 or later. You should not increase this
# version, as doing so will cause the plugin to fail to compile for some
# customers of the plugin.
cmake_minimum_required(VERSION 3.23)
# Set vcpkg root directory
set(VCPKG_ROOT "D:/Projects/Software/Library/vcpkg")
set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake" CACHE STRING "Vcpkg toolchain file")

# Project-level configuration.
set(PROJECT_NAME "nfcsigner")
project(${PROJECT_NAME} LANGUAGES CXX)

# Explicitly opt in to modern CMake behaviors to avoid warnings with recent
# versions of CMake.
cmake_policy(VERSION 3.14...3.25)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "nfcsigner_plugin")

# Any new source files that you add to the plugin should be added here.
list(APPEND PLUGIN_SOURCES
  "nfcsigner_plugin.cpp"
  "nfcsigner_plugin.h"
)

# --- TÌM KIẾM CÁC THƯ VIỆN ĐÃ CÀI ĐẶT QUA VCPKG ---
set(HAVE_PODOFO TRUE)
set(VCPKG_INSTALLED_DIR "${VCPKG_ROOT}/installed/x64-windows")
set(PODOFO_INCLUDE_DIR "${VCPKG_INSTALLED_DIR}/include/")
set(PODOFO_LIBRARY "${VCPKG_INSTALLED_DIR}/lib/podofo.lib")
set(PODOFO_DLL "${VCPKG_INSTALLED_DIR}/bin/podofo.dll")
if(EXISTS "${PODOFO_INCLUDE_DIR}/podofo/podofo.h" AND EXISTS "${PODOFO_LIBRARY}")
    message(STATUS "Found podofo directly")
    # Tạo target thủ công - SHARED vì podofo.dll là dynamic library
    add_library(podofo SHARED IMPORTED)
    set_target_properties(podofo PROPERTIES
            IMPORTED_IMPLIB "${PODOFO_LIBRARY}"
            IMPORTED_LOCATION "${PODOFO_DLL}"
            INTERFACE_INCLUDE_DIRECTORIES "${PODOFO_INCLUDE_DIR}"
    )
else()
    message(WARNING "podofo not found - using raw data mode")
    set(HAVE_PODOFO FALSE)
endif()

# Tìm OpenSSL
find_package(OpenSSL REQUIRED)
# --------------------------------------------------


# Define the plugin library target. Its name must not be changed (see comment
# on PLUGIN_NAME above).
add_library(${PLUGIN_NAME} SHARED
  "include/nfcsigner/nfcsigner_plugin_c_api.h"
  "nfcsigner_plugin_c_api.cpp"
  ${PLUGIN_SOURCES}
)


# Apply a standard set of build settings that are configured in the
# application-level CMakeLists.txt. This can be removed for plugins that want
# full control over build settings.
apply_standard_settings(${PLUGIN_NAME})
# Symbols are hidden by default to reduce the chance of accidental conflicts
# between plugins. This should not be removed; any symbols that should be
# exported should be explicitly exported with the FLUTTER_PLUGIN_EXPORT macro.
set_target_properties(${PLUGIN_NAME} PROPERTIES CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)

# Source include directories and library dependencies. Add any plugin-specific
# dependencies here.
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")

target_include_directories(${PLUGIN_NAME} PUBLIC
        "${CMAKE_CURRENT_SOURCE_DIR}/include"
        # Thêm đường dẫn include cho PoDoFo và OpenSSL
        ${PODOFO_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIRS}
)
if(HAVE_PODOFO)
    target_compile_definitions(${PLUGIN_NAME} PRIVATE HAVE_PODOFO)
    target_link_libraries(${PLUGIN_NAME} PRIVATE podofo)
endif()
target_link_libraries(${PLUGIN_NAME} PRIVATE
        flutter
        flutter_wrapper_plugin
        Winscard
        #podofo_private
        OpenSSL::SSL
        OpenSSL::Crypto
)

# List of absolute paths to libraries that should be bundled with the plugin.
# This list could contain prebuilt libraries, or libraries created by an
# external build triggered from this build file.
set(VCPKG_BIN_DIR "${VCPKG_INSTALLED_DIR}/bin")
set(nfcsigner_bundled_libraries
  "${VCPKG_BIN_DIR}/podofo.dll"
  "${VCPKG_BIN_DIR}/libcrypto-3-x64.dll"
  "${VCPKG_BIN_DIR}/libssl-3-x64.dll"
  "${VCPKG_BIN_DIR}/freetype.dll"
  "${VCPKG_BIN_DIR}/zlib1.dll"
  "${VCPKG_BIN_DIR}/libpng16.dll"
  "${VCPKG_BIN_DIR}/bz2.dll"
  "${VCPKG_BIN_DIR}/brotlidec.dll"
  "${VCPKG_BIN_DIR}/brotlicommon.dll"
  "${VCPKG_BIN_DIR}/liblzma.dll"
  "${VCPKG_BIN_DIR}/jpeg62.dll"
  "${VCPKG_BIN_DIR}/tiff.dll"
  "${VCPKG_BIN_DIR}/iconv-2.dll"
  "${VCPKG_BIN_DIR}/charset-1.dll"
  "${VCPKG_BIN_DIR}/libxml2.dll"
  "${VCPKG_BIN_DIR}/fmt.dll"
  "${VCPKG_BIN_DIR}/utf8proc.dll"
  PARENT_SCOPE
)

# === Tests ===
# These unit tests can be run from a terminal after building the example, or
# from Visual Studio after opening the generated solution file.

# Only enable test builds when building the example (which sets this variable)
# so that plugin clients aren't building the tests.
if (${include_${PROJECT_NAME}_tests})
set(TEST_RUNNER "${PROJECT_NAME}_test")
enable_testing()

# Add the Google Test dependency.
include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/release-1.11.0.zip
)
# Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
# Disable install commands for gtest so it doesn't end up in the bundle.
set(INSTALL_GTEST OFF CACHE BOOL "Disable installation of googletest" FORCE)
FetchContent_MakeAvailable(googletest)

# The plugin's C API is not very useful for unit testing, so build the sources
# directly into the test binary rather than using the DLL.
#add_executable(${TEST_RUNNER}
#  test/nfcsigner_plugin_test.cpp
#  ${PLUGIN_SOURCES}
#)
#apply_standard_settings(${TEST_RUNNER})
#target_include_directories(${TEST_RUNNER} PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
#target_link_libraries(${TEST_RUNNER} PRIVATE flutter_wrapper_plugin)
#target_link_libraries(${TEST_RUNNER} PRIVATE gtest_main gmock)
# flutter_wrapper_plugin has link dependencies on the Flutter DLL.
#add_custom_command(TARGET ${TEST_RUNNER} POST_BUILD
#  COMMAND ${CMAKE_COMMAND} -E copy_if_different
#  "${FLUTTER_LIBRARY}" $<TARGET_FILE_DIR:${TEST_RUNNER}>
#)

# Enable automatic test discovery.
include(GoogleTest)
#gtest_discover_tests(${TEST_RUNNER})
endif()
