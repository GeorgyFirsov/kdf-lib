#
# Configuration flags
#
if (KDFLIB_BUILD_PRETTY_DOCS)
    set(KDFLIB_DOXYGEN_HAVE_DOT         YES)
else (KDFLIB_BUILD_PRETTY_DOCS)
    set(KDFLIB_DOXYGEN_HAVE_DOT         NO)
endif (KDFLIB_BUILD_PRETTY_DOCS)

#
# Setup paths
#
set(KDFLIB_DOCS_VERSION                 ${CMAKE_PROJECT_VERSION})
set(KDFLIB_DOCS_ROOT                    ${KDFLIB_ROOT}/docs)
set(KDFLIB_DOCS_DOXYGEN_AWESOME_ROOT    ${KDFLIB_DOCS_ROOT}/doxygen-awesome-css)
set(KDFLIB_DOCS_DOXYGEN_IN              ${KDFLIB_DOCS_ROOT}/Doxyfile.in)
set(KDFLIB_DOCS_DOXYGEN_OUT             ${KDFLIB_DOCS_ROOT}/Doxyfile)

#
# And here we go...
#
message("[${PROJECT_NAME}]: Configuring doxygen...")

configure_file(${KDFLIB_DOCS_DOXYGEN_IN} 
               ${KDFLIB_DOCS_DOXYGEN_OUT} 
               @ONLY)

#
# In case of GitHub docs we only need a configuration file to be 
# generated, so we quit here in this case
#
if (KDFLIB_BUILD_GITHUB_DOCS)
    message(NOTICE "[${PROJECT_NAME}]: Doxyfile is generated, but KDFLIB_BUILD_GITHUB_DOCS is set, nothing else will be performed")
    message(NOTICE "[${PROJECT_NAME}]: Doxyfile is located here: '${KDFLIB_DOCS_DOXYGEN_OUT}'")
    return()
endif (KDFLIB_BUILD_GITHUB_DOCS)

#
# Otherwise we need to find Doxygen
#
find_package(Doxygen)

#
# Check if we have Doxygen installed
#
if (NOT DOXYGEN_FOUND)
    message(WARNING "[${PROJECT_NAME}]: Doxygen need to be installed to generate the doxygen documentation")
    return()
endif() 

#
# Custom target for building documentation
#
add_custom_target(kdf-lib-docs ALL
    COMMAND ${DOXYGEN_EXECUTABLE} ${KDFLIB_DOCS_DOXYGEN_OUT}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    COMMENT "Generating documentation with Doxygen"
    VERBATIM)