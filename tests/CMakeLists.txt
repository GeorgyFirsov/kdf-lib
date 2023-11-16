#
# Find googletest library
#
find_package(GTest CONFIG REQUIRED)

#
# Directories
#
set(KDFLIB_TESTS_ROOT				            ${KDFLIB_ROOT}/tests)
set(KDFLIB_TESTS_INCLUDE                        ${KDFLIB_TESTS_ROOT}/include)
set(KDFLIB_TESTS_CASES                          ${KDFLIB_TESTS_ROOT}/cases)
set(KDFLIB_TESTS_COVERAGE                       ${KDFLIB_TESTS_ROOT}/coverage)

set(KDFLIB_TESTS_INCLUDE_DIRECTORIES	        ${KDFLIB_INCLUDE_DIRECTORIES}
                                                ${KDFLIB_TESTS_INCLUDE}
                                                ${bc-lib_SOURCE_DIR}/include
                                                ${gtest_SOURCE_DIR}/include 
                                                ${gtest_SOURCE_DIR})

#
# Sources and headers
#
set(KDFLIB_SOURCE_FILES                         )

set(KDFLIB_HEADER_FILES                         ${KDFLIB_TESTS_INCLUDE}/test_data.hpp
                                                ${KDFLIB_TESTS_INCLUDE}/test_common.hpp
                                                ${KDFLIB_TESTS_INCLUDE}/test_utils.hpp)

set(KDFLIB_SOURCES                              ${KDFLIB_SOURCE_FILES}
                                                ${KDFLIB_HEADER_FILES})

#
# Test executable
#
add_executable(kdf-lib-test                     ${KDFLIB_SOURCES})

#
# Include directories
#
target_include_directories(kdf-lib-test PRIVATE ${KDFLIB_TESTS_INCLUDE_DIRECTORIES})

#
# Link with kdf-lib and Google tests
#
target_link_libraries(kdf-lib-test PRIVATE      kdf-lib)
target_link_libraries(kdf-lib-test PRIVATE      GTest::gtest)
target_link_libraries(kdf-lib-test PRIVATE      GTest::gtest_main)

#
# Add target as test
#
add_test(NAME kdf-lib-test 
         COMMAND kdf-lib-test)

#
# Create code coverage reporting script
#
string(REPLACE "/" "\\" KDFLIB_COV_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_RUNTIME_OUTPUT_DIRECTORY})

configure_file(${KDFLIB_TESTS_COVERAGE}/coverage.cmd.in
               ${CMAKE_BINARY_DIR}/coverage.cmd
               @ONLY)