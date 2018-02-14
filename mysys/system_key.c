/* Copyright (c) 2018 Percona LLC and/or its affiliates. All rights reserved. */

#include "system_key.h"
#include <stdlib.h>
#include "my_sys.h"

/** 
   System keys cannot have ':' in their name. We use ':' as a separator between
   system key's name and system key's version.
*/
const char* valid_percona_system_keys[] = {PERCONA_BINLOG_KEY_NAME};
const size_t valid_percona_system_keys_size = array_elements(valid_percona_system_keys);

uchar* parse_system_key(const uchar *key, const size_t key_length, uint *key_version,
                        uchar **key_data, size_t *key_data_length)
{
  size_t key_version_length= 0;
  ulong ulong_key_version= 0;
  char *version= NULL, *endptr= NULL;

  if (key == NULL || key_length == 0)
    return NULL;

  for (; key[key_version_length] != ':' && key_version_length < key_length; ++key_version_length);
  if (key_version_length == 0 || key_version_length == key_length)
    return NULL; // no version found

  version= (char*)(my_malloc(PSI_NOT_INSTRUMENTED, key_version_length+1, MYF(0)));
  if (version == NULL)
    return NULL;

  memcpy(version, key, key_version_length);
  version[key_version_length]= '\0';
  endptr= version;

  ulong_key_version= strtoul(version, &endptr, 10);
  if (ulong_key_version > UINT_MAX || *endptr != '\0')
  {
    my_free(version);
    return NULL; // conversion failed
  }

  DBUG_ASSERT(ulong_key_version <= UINT_MAX); // sanity check

  *key_data_length= key_length - (key_version_length + 1); // skip ':' after key version
  if (*key_data_length == 0)
  {
    my_free(version);
    return NULL;
  }
  DBUG_ASSERT(*key_data_length <= 512);

  *key_data= (uchar*)(my_malloc(PSI_NOT_INSTRUMENTED, sizeof(uchar)*(*key_data_length), MYF(0)));
  if (*key_data == NULL)
  {
    my_free(version);
    return NULL;
  }

  memcpy(*key_data, key+key_version_length+1, *key_data_length); // skip ':' after key version
  **key_version= (uint)ulong_key_version;
  return *key_data;
}
