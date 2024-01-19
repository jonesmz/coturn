##
# 3-Clause BSD License: https://opensource.org/license/bsd-3-clause/
#
# Copyright (C) 2021 Kang Lin <kl222@126.com>
#
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. Neither the name of the project nor the names of its contributors
#    may be used to endorse or promote products derived from this software
#    without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
##

configure_file("${CMAKE_SOURCE_DIR}/cmake/CMakeCPackOptions.cmake.in"
	"${CMAKE_BINARY_DIR}/CMakeCPackOptions.cmake" @ONLY)
set(CPACK_PROJECT_CONFIG_FILE "${CMAKE_BINARY_DIR}/CMakeCPackOptions.cmake")

# Generate .txt license file for CPack (PackageMaker requires a file extension)
configure_file(${CMAKE_SOURCE_DIR}/LICENSE ${CMAKE_BINARY_DIR}/LICENSE.txt @ONLY)

SET(CPACK_BINARY_ZIP "ON")

set(CPACK_SOURCE_IGNORE_FILES
    ${CMAKE_SOURCE_DIR}/build
    ${CMAKE_SOURCE_DIR}/.cache
    ${CMAKE_SOURCE_DIR}/.git
    ${CMAKE_SOURCE_DIR}/.github
    ${CMAKE_SOURCE_DIR}/.gitignore
    ${CMAKE_SOURCE_DIR}/.dockerignore
    ${CMAKE_SOURCE_DIR}/CMakeCache.txt)

set(CPACK_SYSTEM_NAME "${CMAKE_SYSTEM_NAME}_${CMAKE_SYSTEM_PROCESSOR}")
set(CPACK_TOPLEVEL_TAG "${CMAKE_SYSTEM_NAME}_${CMAKE_SYSTEM_PROCESSOR}")
string(TOLOWER ${CMAKE_PROJECT_NAME} CMAKE_PROJECT_NAME_lower)
set(CPACK_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME_lower}_${BUILD_VERSION}_${CPACK_SYSTEM_NAME}")
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${CMAKE_PROJECT_NAME_lower}_${BUILD_VERSION}_${CPACK_SYSTEM_NAME}")
#set(CPACK_PACKAGE_DIRECTORY ${CMAKE_BINARY_DIR}/package)

set(CPACK_PACKAGE_NAME "coturn")
set(CPACK_PACKAGE_VENDOR "coturn")
set(CPACK_PACKAGE_VERSION ${BUILD_VERSION})
SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "coturn: Free open source implementation of TURN and STUN Server")
#set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_SOURCE_DIR}/README.md")
#set(CPACK_RESOURCE_FILE_WELCOME )
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_BINARY_DIR}/LICENSE.txt")
set(CPACK_PACKAGE_HOMEPAGE_URL "https://github.com/coturn/coturn")
set(CPACK_PACKAGE_CONTACT "misi <misi@majd.eu>")

set(CPACK_PACKAGE_INSTALL_DIRECTORY "coturn")
set(CPACK_PACKAGE_CHECKSUM "MD5")

############### Debian ###################
if(UNIX)
	set(CPACK_BINARY_DEB ON)
endif()
set(CPACK_DEBIAN_PACKAGE_SOURCE coturn)
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "misi <misi@majd.eu>")
#set(CPACK_DEBIAN_ARCHITECTURE ${CMAKE_SYSTEM_PROCESSOR})
set(CPACK_DEBIAN_PACKAGE_SECTION "main")
set(CPACK_DEBIAN_PACKAGE_PREDEPENDS "debhelper (>= 6), cmake (>= 2.8.0), dh-systemd (>= 1.5)")
#set(CMAKE_INSTALL_RPATH )
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
#set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS_POLICY ">=")
#set(CPACK_DEBIAN_PACKAGE_CONTROL_EXTRA
#    "${CMAKE_CURRENT_SOURCE_DIR}/prerm;${CMAKE_CURRENT_SOURCE_DIR}/postrm")
############### Debian ###################

#set(CPACK_PACKAGE_EXECUTABLES turnadmin turnclient)
#set(CPACK_CREATE_DESKTOP_LINKS turnadmin turnclient)

############### NSIS ###################
if(WIN32)
	set(CPACK_BINARY_NSIS ON)
endif()
#set(CPACK_NSIS_INSTALL_ROOT "$LOCALAPPDATA")
set(CPACK_NSIS_MODIFY_PATH ON)
set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
#set(CPACK_PACKAGE_ICON "${CMAKE_SOURCE_DIR}/resources\\\\coturn_Install.bmp")
#set(CPACK_NSIS_MUI_ICON "${CMAKE_SOURCE_DIR}/resources\\\\coturn_Icon_96px.ico")
#set(CPACK_NSIS_MUI_UNICON "${CMAKE_SOURCE_DIR}/resource\\\\coturn_Icon_96px.ico")
############### NSIS ###################

#set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE )
set(CPACK_COMPONENTS_ALL Runtime Development)

SET(CMAKE_INSTALL_SYSTEM_RUNTIME_COMPONENT Runtime)
include(InstallRequiredSystemLibraries)
include(CPackComponent)
include(CPack)

cpack_add_component(Development
    DISPLAY_NAME  "Development"
    DESCRIPTION   "Development"
    DEPENDS Runtime
    )

cpack_add_component(Runtime
    DISPLAY_NAME  "Runtime"
    DESCRIPTION   "Runtime"
    )
