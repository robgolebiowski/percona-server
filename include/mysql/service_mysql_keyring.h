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
#include <stdlib.h>

// System keys cannot have ':' in their name. We use ':' as a separator between
// system key's name and system key's verision
// Keep adding keys' names to valid_percona_system_keys in sorted order. We later do binary_search
// on this table. Also update valid_percona_system_keys_size.
MY_ATTRIBUTE((unused)) static const size_t valid_percona_system_keys_size = 1;
MY_ATTRIBUTE((unused)) static const char* valid_percona_system_keys[] = {"percona_binlog"};

// Unused attribute can only be used with declaration - thus first there is a declaration of 
// parse_system_key and then the defintion follows.
static uchar* parse_system_key(const unsigned char *key, const size_t key_length, unsigned int *key_version,
                               unsigned char **key_data, size_t *key_data_length) MY_ATTRIBUTE((unused));

static uchar* parse_system_key(const unsigned char *key, const size_t key_length, unsigned int *key_version,
                               unsigned char **key_data, size_t *key_data_length)
{
  unsigned int key_version_length= 0;
  unsigned long ulong_key_version= 0;
  char *version= 0, *endptr= 0;

  if (key_length == 0)
    return 0;

  for (; key[key_version_length] != ':' && key_version_length < key_length; ++key_version_length);
  if (key_version_length == 0 || key_version_length == key_length)
    return 0; //no version found

  version= (char*)(my_malloc(PSI_NOT_INSTRUMENTED, sizeof(char)*key_version_length+1, MYF(0)));
  if (version == 0)
    return 0;

  memcpy(version, key, key_version_length);
  version[key_version_length]= '\0';
  endptr= version;

  ulong_key_version= strtoul(version, &endptr, 10);
  if (ulong_key_version > UINT_MAX || *endptr != '\0')
  {
    my_free(version);
    return 0; // convertion failed
  }

  DBUG_ASSERT(ulong_key_version <= UINT_MAX); // sanity check
  *key_version= (unsigned int)ulong_key_version;

  my_free(version);

  *key_data_length= key_length - (key_version_length + 1); // skip ':' after key version
  if (*key_data_length == 0)
    return 0;
  DBUG_ASSERT(*key_data_length <= 512);

  *key_data= (uchar*)(my_malloc(PSI_NOT_INSTRUMENTED, sizeof(uchar)*(*key_data_length), MYF(0)));
  if (*key_data == 0)
    return 0;

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

