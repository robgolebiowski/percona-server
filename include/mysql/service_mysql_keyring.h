/* Copyright (c) 2014, 2016 Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifndef MYSQL_SERVICE_MYSQL_PLUGIN_KEYRING_INCLUDED
#define MYSQL_SERVICE_MYSQL_PLUGIN_KEYRING_INCLUDED

#ifndef MYSQL_ABI_CHECK
#include "m_string.h"
// The caller must make sure this is properly formatted system key, i.e. it consist of 

static uchar* parse_system_key(const uchar *key, const size_t key_length, uint *key_version,
                               uchar **key_data, size_t *key_data_length) MY_ATTRIBUTE((unused));

static uchar* parse_system_key(const uchar *key, const size_t key_length, uint *key_version,
                               uchar **key_data, size_t *key_data_length)
{
  char *version = 0;
  uint key_version_length = 0;
  long key_version_long = 0;

  for (; key[key_version_length] != ':' && key_version_length < key_length; ++key_version_length);
  if (key_version_length == key_length)
    return (uchar*)NullS; //no version found

  version= (char*)(my_malloc(PSI_NOT_INSTRUMENTED, sizeof(char)*key_version_length+1, MYF(0)));
  if (version == 0)
    return (uchar*)NullS;

  memcpy(version, key, key_version_length);
  version[key_version_length]= '\0';

  if (str2int(version, 10, 0, UINT_MAX, &key_version_long) == NullS)
  {
    my_free(version);
    return (uchar*)NullS;
  }
  my_free(version);
  DBUG_ASSERT(key_version_long >= 0 && key_version_long <= UINT_MAX); // sanity check
  *key_version = (uint)key_version_long;

  *key_data_length= key_length - (key_version_length + 1); // skip ':' after key version
  if (*key_data_length == 0)
    return (uchar*)NullS;
  DBUG_ASSERT(*key_data_length < 512);

  *key_data= (uchar*)(my_malloc(PSI_NOT_INSTRUMENTED, sizeof(uchar)*(*key_data_length), MYF(0)));
  if (*key_data == 0)
    return (uchar*)NullS;

  memcpy(*key_data, key+key_version_length+1, *key_data_length); // skip ':' after key version
  return *key_data;
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
extern struct mysql_keyring_service_st
{
  int (*my_key_store_func)(const char *, const char *, const char *,
                           const void *, size_t);
  int (*my_key_fetch_func)(const char *, char **, const char *, void **,
                           size_t *);
  int (*my_key_remove_func)(const char *, const char *);
  int (*my_key_generate_func)(const char *, const char *, const char *,
                              size_t);
} *mysql_keyring_service;

#ifdef MYSQL_DYNAMIC_PLUGIN

#define my_key_store(key_id, key_type, user_id, key, key_len) \
  mysql_keyring_service->my_key_store_func(key_id, key_type, user_id, key, \
                                           key_len)
#define my_key_fetch(key_id, key_type, user_id, key, key_len) \
  mysql_keyring_service->my_key_fetch_func(key_id, key_type, user_id, key, \
                                           key_len)
#define my_key_remove(key_id, user_id) \
  mysql_keyring_service->my_key_remove_func(key_id, user_id)
#define my_key_generate(key_id, key_type, user_id, key_len) \
  mysql_keyring_service->my_key_generate_func(key_id, key_type, user_id, \
                                              key_len)
#else

int my_key_store(const char *, const char *, const char *, const void *, size_t);
int my_key_fetch(const char *, char **, const char *, void **,
                 size_t *);
int my_key_remove(const char *, const char *);
int my_key_generate(const char *, const char *, const char *, size_t);

#endif

#ifdef __cplusplus
}
#endif

#endif //MYSQL_SERVICE_MYSQL_PLUGIN_KEYRING_INCLUDED

