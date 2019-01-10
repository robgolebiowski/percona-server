/* Copyright (c) 2018 Percona LLC and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or
   modify it under the terms of the GNU General Public License
   as published by the Free Software Foundation; version 2 of
   the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA */

#ifndef DD_INIT_MODE_T_H_INCLUDED
#define DD_INIT_MODE_T_H_INCLUDED

/** Mode for initializing the data dictionary. */
enum dict_init_mode_t {
  DICT_INIT_CREATE_FILES,      //< Create all required SE files
  DICT_INIT_CHECK_FILES,       //< Verify existence of expected files
  DICT_INIT_UPGRADE_57_FILES,  //< Used for upgrade from mysql-5.7
  DICT_INIT_IGNORE_FILES       //< Don't care about files at all
};


#endif //DD_INIT_MODE_T_H_INCLUDED


