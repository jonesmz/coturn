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

#
# Find Prometheus.
#
# Set this variable to any additional path you want the module to search:
#  Prometheus_DIR or Prometheus_ROOT
#
# Try to find prometheus
# Once done, this will define:
#  Prometheus_FOUND        - Prometheus (or all requested components of prom, microhttpd) was found.
#  Prometheus_INCLUDE_DIRS - Libevent include directories
#  Prometheus_LIBRARIES    - libraries needed to use Prometheus
#

include(FindPackageHandleStandardArgs)

find_package(PkgConfig)
pkg_check_modules(PC_prom QUIET prom)
pkg_check_modules(PC_microhttd QUIET microhttpd)

find_path(microhttpd_include_dir
    NAMES microhttpd.h
    HINTS ${Prometheus_DIR} ${Prometheus_ROOT} ${PC_microhttd_INCLUDE_DIRS} /usr
    PATHS $ENV{Prometheus_DIR} $ENV{Prometheus_ROOT}
    PATH_SUFFIXES include
    )

find_library(
    microhttpd_libs
    NAMES microhttpd
    HINTS ${Prometheus_DIR} ${Prometheus_ROOT} ${PC_microhttd_LIBRARY_DIRS}
    PATHS $ENV{Prometheus_DIR} $ENV{Prometheus_ROOT}
    PATH_SUFFIXES lib ${CMAKE_INSTALL_LIBDIR})

find_path(prom_INCLUDE_DIR
    NAMES prom.h
    HINTS ${Prometheus_DIR} ${Prometheus_ROOT} ${PC_prom_INCLUDE_DIRS} /usr
    PATHS $ENV{Prometheus_DIR} $ENV{Prometheus_ROOT}
    PATH_SUFFIXES include
    )

find_library(
    prom_libs
    NAMES prom
    HINTS ${Prometheus_DIR} ${Prometheus_ROOT} ${PC_prom_LIBRARY_DIRS}
    PATHS $ENV{Prometheus_DIR} $ENV{Prometheus_ROOT}
    PATH_SUFFIXES lib ${CMAKE_INSTALL_LIBDIR})

find_package_handle_standard_args(Prometheus
    REQUIRED_VARS prom_libs prom_INCLUDE_DIR
        microhttpd_include_dir microhttpd_libs
        )

set(Prometheus_INCLUDE_DIRS
    ${prom_INCLUDE_DIR}
    ${microhttpd_include_dir})
set(Prometheus_LIBRARIES ${prom_libs} ${microhttpd_libs})
