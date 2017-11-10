/* Copyright (c) 2016, 2017, Oracle and/or its affiliates. All rights reserved.

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

#include <my_global.h>
#include <sstream>
#include "keyring.h"

namespace keyring
{
/* Always defined. */
  PSI_memory_key key_memory_KEYRING;
  PSI_rwlock_key key_LOCK_keyring;
}

extern mysql_rwlock_t LOCK_keyring;

boost::movelib::unique_ptr<IKeys_container> keys(NULL);
volatile my_bool is_keys_container_initialized= FALSE;
boost::movelib::unique_ptr<ILogger> logger(NULL);
boost::movelib::unique_ptr<char[]> keyring_file_data(NULL);

#ifdef HAVE_PSI_INTERFACE
static PSI_rwlock_info all_keyring_rwlocks[]=
{
  {&keyring::key_LOCK_keyring, "LOCK_keyring", 0}
};

static PSI_memory_info all_keyring_memory[]=
{
  {&keyring::key_memory_KEYRING, "KEYRING", 0}
};

void keyring_init_psi_keys(void)
{
  const char *category = "keyring";
  int count;

  count= array_elements(all_keyring_memory);
  mysql_memory_register(category, all_keyring_memory, count);

  count= array_elements(all_keyring_rwlocks);
  mysql_rwlock_register(category, all_keyring_rwlocks, count);
}
#endif //HAVE_PSI_INTERFACE

int init_keyring_locks()
{
  return mysql_rwlock_init(keyring::key_LOCK_keyring, &LOCK_keyring);
}

my_bool is_key_length_and_type_valid(const char *key_type, size_t key_len)
{
  my_bool is_key_len_valid= FALSE;
  my_bool is_type_valid= TRUE;

  if(strcmp(key_type, "AES") == 0)
    is_key_len_valid= (key_len == 16 || key_len == 24 || key_len == 32);
  else if (strcmp(key_type, "RSA") == 0)
    is_key_len_valid= (key_len == 128 || key_len == 256 || key_len == 512);
  else if (strcmp(key_type, "DSA") == 0)
    is_key_len_valid= (key_len == 128 || key_len == 256 || key_len == 384);
  else
  {
    is_type_valid= FALSE;
    logger->log(MY_ERROR_LEVEL, "Invalid key type");
  }

  if (is_type_valid == TRUE && is_key_len_valid == FALSE)
    logger->log(MY_ERROR_LEVEL, "Invalid key length for given block cipher");

  return is_type_valid && is_key_len_valid;
}

void log_operation_error(const char *failed_operation, const char *plugin_name)
{
 if (logger != NULL)
 {
   std::ostringstream err_msg;
   err_msg << "Failed to " << failed_operation << " due to internal exception inside "
           << plugin_name << " plugin";
   logger->log(MY_ERROR_LEVEL, err_msg.str().c_str());
 }
}

my_bool create_keyring_dir_if_does_not_exist(const char *keyring_file_path)
{
  if (!keyring_file_path || strlen(keyring_file_path) == 0)
    return TRUE;
  char keyring_dir[FN_REFLEN];
  size_t keyring_dir_length;
  dirname_part(keyring_dir, keyring_file_path, &keyring_dir_length);
  if (keyring_dir_length > 1 && (keyring_dir[keyring_dir_length-1] == FN_LIBCHAR))
  {
    keyring_dir[keyring_dir_length-1]= '\0';
    --keyring_dir_length;
  }
  int flags=
#ifdef _WIN32
    0
#else
    S_IRWXU | S_IRGRP | S_IXGRP
#endif
    ;
  /*
    If keyring_dir_length is 0, it means file
    is being created current working directory
  */
  if (strlen(keyring_dir) != 0)
   my_mkdir(keyring_dir, flags, MYF(0));
  return FALSE;
}

void update_keyring_file_data(MYSQL_THD thd  MY_ATTRIBUTE((unused)),
                              struct st_mysql_sys_var *var  MY_ATTRIBUTE((unused)),
                              void *var_ptr MY_ATTRIBUTE((unused)),
                              const void *save_ptr)
{
  mysql_rwlock_wrlock(&LOCK_keyring);
  IKeys_container *new_keys= *reinterpret_cast<IKeys_container**>(const_cast<void*>(save_ptr));
  keys.reset(new_keys);
  keyring_file_data.reset(new char[new_keys->get_keyring_storage_url().length()+1]);
  memcpy(keyring_file_data.get(), new_keys->get_keyring_storage_url().c_str(),
         new_keys->get_keyring_storage_url().length()+1);
  *reinterpret_cast<char **>(var_ptr)= keyring_file_data.get();
  is_keys_container_initialized= TRUE;
  mysql_rwlock_unlock(&LOCK_keyring);
}

my_bool mysql_key_fetch(boost::movelib::unique_ptr<IKey> key_to_fetch, char **key_type,
                        void **key, size_t *key_len)
{
  if (is_keys_container_initialized == FALSE)
    return TRUE;

  if (key_to_fetch->is_key_id_valid() == FALSE)
  {
    logger->log(MY_ERROR_LEVEL,
                "Error while fetching key: key_id cannot be empty");
    return TRUE;
  }
  mysql_rwlock_rdlock(&LOCK_keyring);
  IKey *fetched_key = keys->fetch_key(key_to_fetch.get());
  mysql_rwlock_unlock(&LOCK_keyring);
  if (fetched_key)
  {
    *key_len = fetched_key->get_key_data_size();
    fetched_key->xor_data();
    *key= static_cast<void*>(fetched_key->release_key_data());
    *key_type= my_strdup(keyring::key_memory_KEYRING,
                         fetched_key->get_key_type()->c_str(),
                         MYF(MY_WME));
  }
  else
    *key = NULL;
  return FALSE;
}

my_bool check_key_for_writing(IKey* key, std::string error_for)
{
  std::string error_msg= "Error while ";
  error_msg+= error_for;
  if (key->is_key_type_valid() == FALSE)
  {
    error_msg+= " key: invalid key_type";
    logger->log(MY_ERROR_LEVEL, error_msg.c_str());
    return TRUE;
  }
  if (key->is_key_id_valid() == FALSE)
  {
    error_msg+= " key: key_id cannot be empty";
    logger->log(MY_ERROR_LEVEL, error_msg.c_str());
    return TRUE;
  }
 return FALSE;
}

my_bool mysql_key_store(boost::movelib::unique_ptr<IKey> key_to_store)
{
  if (is_keys_container_initialized == FALSE)
    return TRUE;

  if (check_key_for_writing(key_to_store.get(), "storing"))
    return TRUE;

  if (key_to_store->get_key_data_size() > 0)
    key_to_store->xor_data();
  mysql_rwlock_wrlock(&LOCK_keyring);
  if (keys->store_key(key_to_store.get()))
  {
    mysql_rwlock_unlock(&LOCK_keyring);
    return TRUE;
  }
  mysql_rwlock_unlock(&LOCK_keyring);

  key_to_store.release();
  return FALSE;
}

my_bool mysql_key_remove(boost::movelib::unique_ptr<IKey> key_to_remove)
{
  bool retval= false;
  if (is_keys_container_initialized == FALSE)
    return TRUE;
  if (key_to_remove->is_key_id_valid() == FALSE)
  {
    logger->log(MY_ERROR_LEVEL,
                "Error while removing key: key_id cannot be empty");
    return TRUE;
  }
  mysql_rwlock_wrlock(&LOCK_keyring);
  retval= keys->remove_key(key_to_remove.get());
  mysql_rwlock_unlock(&LOCK_keyring);
  return retval;
}

struct System_key_info
{
  System_key_info(const char *id, const char *type,
                  size_t length)
  : id(id), type(type), length(length)
  {}
               
  std::string id;
  std::string type;
  size_t length;
};

my_bool mysql_key_generate(const char *key_id, const char *key_type,
                           const char *user_id, size_t key_len);
my_bool mysql_key_fetch(const char *key_id, char **key_type, const char *user_id,
                        void **key, size_t *key_len);

static bool generate_system_key_if_doesnot_exist(System_key_info &key_info)
{
  char *key_type= NULL, *key= NULL;
  size_t key_length;
  
  bool failure= mysql_key_fetch(key_info.id.c_str(), &key_type, NULL, (void**)&key, &key_length);
  failure= failure || (key != NULL && (key_type == NULL || key_info.type != key_type));
  if (!failure && key == NULL) //no failure, but key does not exist
    failure= mysql_key_generate(key_info.id.c_str(), key_info.type.c_str(), NULL, key_info.length);

  if (key != NULL)
    my_free(key);
  if (key_type != NULL)
    my_free(key_type);

  return failure;
}

bool init_system_keys()
{
  std::vector<System_key_info> system_keys_info;
  System_key_info percona_binlog_key("percona_binlog", "AES", 16);
  system_keys_info.push_back(percona_binlog_key);
  bool failure = false;

  // This is last step of initialization, so we need to trick the container that it is
  // fully initialized so it would allow us to store system keys
  is_keys_container_initialized = TRUE;
  for (std::vector<System_key_info>::iterator iter = system_keys_info.begin();
       iter != system_keys_info.end() && failure == false;
       ++iter)
    failure = generate_system_key_if_doesnot_exist(*iter);

  is_keys_container_initialized = FALSE;
  return failure;
  
  is_keys_container_initialized = FALSE;

  return failure;
}

