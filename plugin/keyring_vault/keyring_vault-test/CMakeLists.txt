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

ADD_EXECUTABLE(keyring_vault-test
               ./keyring_vault-test.cc
               ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keyring_key.cc
               ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keys_container.cc
               ${CMAKE_SOURCE_DIR}/plugin/keyring/common/keyring_impl.cc
               ../vault_io.cc
               ../vault_key.cc
               ../vault_parser.cc
               ../vault_keys_list.cc
               ../vault_keys_container.cc
               ../vault_curl.cc
               ../vault_credentials_parser.cc)

TARGET_LINK_LIBRARIES(keyring_vault-test strings dbug regex mysys sql)
TARGET_LINK_LIBRARIES(keyring_vault-test binlog rpl master slave)
TARGET_LINK_LIBRARIES(keyring_vault-test ${CURL_LIBRARY} ${SSL_LIBRARIES})
