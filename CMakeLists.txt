cmake_minimum_required(VERSION 3.5.0)
project(kdf-lib VERSION 1.0.0)

#
# Global config
#
set(CMAKE_CXX_STANDARD                                  20)
set(CMAKE_CXX_STANDARD_REQUIRED                         True)

#
# Options
#
option(KDFLIB_KERNEL_MODE                               "Build kdf-lib for kernel mode too (Windows only)." OFF)
option(KDFLIB_GENERATE_DOCS                             "Generate documentation for kdf-lib." OFF)
option(KDFLIB_DOCS_ONLY                                 "Generate documentation only (kdf-lib will not be built." OFF)
option(KDFLIB_GITHUB_DOCS                               "Generate documentation for GitHub." OFF)
option(KDFLIB_PRETTY_DOCS                               "Use graphwiz for diagrams." OFF)
option(KDFLIB_ENABLE_TESTING                            "Enable testing of ciphers, modes of operation and other functions." ON)

#
# Configuration
#
if (WIN32)
    set(KDFLIB_WINDOWS_BUILD                            ON)
else (WIN32)
    set(KDFLIB_WINDOWS_BUILD                            OFF)
endif (WIN32)

if (KDFLIB_GENERATE_DOCS AND KDFLIB_DOCS_ONLY)

    #
    # Building docs only
    #

    set(KDFLIB_BUILD_LIB                                OFF)
    set(KDFLIB_BUILD_TESTS                              OFF)
    set(KDFLIB_BUILD_DOCS                               ON)
    set(KDFLIB_BUILD_GITHUB_DOCS                        ${KDFLIB_GITHUB_DOCS})
    set(KDFLIB_BUILD_PRETTY_DOCS                        ${KDFLIB_PRETTY_DOCS})

    #
    # Just set this to OFF, because no binary is built
    #
    set(KDFLIB_BUILD_KERNEL_LIB                         OFF)

else (KDFLIB_GENERATE_DOCS AND KDFLIB_DOCS_ONLY)

    #
    # Here I assume other flags, but library 
    # will be built always here.
    #

    set(KDFLIB_BUILD_LIB                                ON)
    set(KDFLIB_BUILD_TESTS                              ${KDFLIB_ENABLE_TESTING})
    set(KDFLIB_BUILD_DOCS                               ${KDFLIB_GENERATE_DOCS})
    set(KDFLIB_BUILD_GITHUB_DOCS                        ${KDFLIB_GITHUB_DOCS})
    set(KDFLIB_BUILD_PRETTY_DOCS                        ${KDFLIB_PRETTY_DOCS})

    #
    # Kernel mode library is supporten on Windows only
    #
    if (KDFLIB_WINDOWS_BUILD)

        set(KDFLIB_BUILD_KERNEL_LIB                     ${KDFLIB_KERNEL_MODE})
        
    else (KDFLIB_WINDOWS_BUILD)

        message(STATUS "[${PROJECT_NAME}]: Non-Windows version, KDFLIB_BUILD_KERNEL_LIB will set to OFF.")
        set(KDFLIB_BUILD_KERNEL_LIB                     OFF)

    endif (KDFLIB_WINDOWS_BUILD)

endif (KDFLIB_GENERATE_DOCS AND KDFLIB_DOCS_ONLY)

message("[${PROJECT_NAME}]: KDFLIB_WINDOWS_BUILD     = ${KDFLIB_WINDOWS_BUILD}")
message("[${PROJECT_NAME}]: KDFLIB_BUILD_LIB         = ${KDFLIB_BUILD_LIB}")
message("[${PROJECT_NAME}]: KDFLIB_BUILD_KERNEL_LIB  = ${KDFLIB_BUILD_KERNEL_LIB}")
message("[${PROJECT_NAME}]: KDFLIB_BUILD_TESTS       = ${KDFLIB_BUILD_TESTS}")
message("[${PROJECT_NAME}]: KDFLIB_BUILD_DOCS        = ${KDFLIB_BUILD_DOCS}")
message("[${PROJECT_NAME}]: KDFLIB_BUILD_GITHUB_DOCS = ${KDFLIB_BUILD_GITHUB_DOCS}")
message("[${PROJECT_NAME}]: KDFLIB_BUILD_PRETTY_DOCS = ${KDFLIB_BUILD_PRETTY_DOCS}")

#
# Just sanity check if we are going well
#
if (NOT KDFLIB_BUILD_LIB AND KDFLIB_BUILD_TESTS)
    message(FATAL_ERROR "[${PROJECT_NAME}]: cannot build tests without building kdf-lib itself")
endif (NOT KDFLIB_BUILD_LIB AND KDFLIB_BUILD_TESTS)

#
# Set global directories
#
set(KDFLIB_ROOT		                                    ${CMAKE_CURRENT_LIST_DIR})
set(KDFLIB_SOURCES_ROOT								    ${KDFLIB_ROOT}/src)
set(KDFLIB_INCLUDE_ROOT								    ${KDFLIB_ROOT}/include)
set(KDFLIB_INCLUDE_DIRECTORIES						    ${KDFLIB_INCLUDE_ROOT})

#
# Set output directories for all targets
#
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY                      ${CMAKE_BINARY_DIR}/out)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY                      ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY                      ${CMAKE_BINARY_DIR}/lib)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE              ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_RELEASE              ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_RELEASE              ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG                ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_DEBUG                ${CMAKE_LIBRARY_OUTPUT_DIRECTORY})
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_DEBUG                ${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

#
# Now let's build targets according to the flags set before
#
if (KDFLIB_BUILD_LIB)
    
    #
    # FindWDK module
    #
    list(APPEND CMAKE_MODULE_PATH	                    ${CMAKE_SOURCE_DIR}/third-party/FindWDK/cmake)
    
    #
    # Preprocessor definitions
    #
    add_compile_definitions(UNICODE)

    #
    # Implementation directories
    #
    set(KDFLIB_KDFS_SOURCES_DIR						    ${KDFLIB_SOURCES_ROOT}/kdfs)
    set(KDFLIB_KDFS_INCLUDE_DIR						    ${KDFLIB_INCLUDE_ROOT}/kdfs)

    set(KDFLIB_INTERNAL_INCLUDE_DIRECTORIES             ${KDFLIB_INCLUDE_DIRECTORIES})

    set(KDFLIB_R1323665_1_022-2018_SOURCES_DIR			${KDFLIB_KDFS_SOURCES_DIR}/r1323665_1_022-2018)
    set(KDFLIB_R1323665_1_022-2018_INCLUDE_DIR			${KDFLIB_KDFS_INCLUDE_DIR}/r1323665_1_022-2018)

    #
    # Source files
    #
    set(KDFLIB_SOURCE_FILES								${KDFLIB_R1323665_1_022-2018_SOURCES_DIR}/kdf.c)

    set(KDFLIB_HEADER_FILES								${KDFLIB_R1323665_1_022-2018_INCLUDE_DIR}/kdf.h
                                                        ${KDFLIB_INCLUDE_ROOT}/kdflib.h)

    set(KDFLIB_SOURCES									${KDFLIB_SOURCE_FILES}
                                                        ${KDFLIB_HEADER_FILES})

    #
    # Library itself (may be built for user mode as 
    # well as for kernel mode)
    #
    add_library(kdf-lib									${KDFLIB_SOURCES})

    if (KDFLIB_BUILD_KERNEL_LIB)
        message("[${PROJECT_NAME}]: Building additional target for kernel mode")

        find_package(WDK REQUIRED)
        wdk_add_library(kdf-lib-km						${KDFLIB_SOURCES})
    endif (KDFLIB_BUILD_KERNEL_LIB)


    #
    # Include directories
    #
    target_include_directories(kdf-lib PRIVATE 			${KDFLIB_INTERNAL_INCLUDE_DIRECTORIES})

    if (KDFLIB_BUILD_KERNEL_LIB)
        target_include_directories(kdf-lib-km PRIVATE 	${KDFLIB_INTERNAL_INCLUDE_DIRECTORIES})
    endif (KDFLIB_BUILD_KERNEL_LIB)


    #
    # On non-Windows builds it is necessary to add some intrinsics support
    #
    if (NOT KDFLIB_WINDOWS_BUILD)
        target_compile_options(kdf-lib PRIVATE          -msse2)
    endif (NOT KDFLIB_WINDOWS_BUILD)

endif (KDFLIB_BUILD_LIB)

if (KDFLIB_BUILD_TESTS)

    include(CTest)

    #
    # Tests target
    #
    add_subdirectory(tests)

endif (KDFLIB_BUILD_TESTS)

if (KDFLIB_BUILD_DOCS)

    #
    # Docs target
    #
    add_subdirectory(docs)

endif (KDFLIB_BUILD_DOCS)