# Copyright (c) 2016, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA

INCLUDE_DIRECTORIES(${BOOST_PATCHES_DIR})
INCLUDE_DIRECTORIES(SYSTEM ${BOOST_INCLUDE_DIR})
INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR}/common)

INCLUDE_DIRECTORIES(
  ${CMAKE_SOURCE_DIR}/plugin/keyring/common
  /home/rob/curl/include)

MYSQL_ADD_PLUGIN(keyring_vault
                 vault_io.cc
                 vault_key.cc
                 vault_parser.cc
                 vault_keys_list.cc
                 vault_keys_container.cc
                 vault_curl.cc
                 vault_credentials_parser.cc
                 vault_keyring.cc
                 MODULE_ONLY
                 MODULE_OUTPUT_NAME "keyring_vault")

#IF(SSL_DEFINES)
#  ADD_DEFINITIONS(${SSL_DEFINES})
#ENDIF()
#
#IF(WITH_KEYRING_TEST)
#  ADD_SUBDIRECTORY(keyring-test)
#ENDIF()
#
IF(HAVE_DLOPEN)
    SET(DYNLIB_EXTENSION "so")
    SET_TARGET_PROPERTIES(keyring_vault
      PROPERTIES LINK_FLAGS "${CMAKE_SHARED_LIBRARY_C_FLAGS}")
ENDIF()
