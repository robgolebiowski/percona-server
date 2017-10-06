#include "system_keys_container.h"

namespace keyring {

System_keys_container::System_keys_container()
{
  KeyIdAndVersion percona_binlog_key_mock("percona_binlog:-1", -1); 
  system_key_id_to_key_id.insert(std::make_pair("percona_binlog", percona_binlog_key_mock));
}

bool System_keys_container::is_system_key(IKey *key)
{
  std::string system_key_id;
  long key_version;

  return is_system_key(key, system_key_id, key_version);
}

std::string System_keys_container::get_latest_key_id_if_system_key(IKey *key)
{
  std::string *key_id = key->get_key_id();
  return system_key_id_to_key_id.count(*key_id) == 0 ?
         "" : system_key_id_to_key_id[*key_id].key_id;
}

bool System_keys_container::is_system_key(IKey *key, std::string &system_key_id, long &key_version)
{
  std::size_t colon_position= std::string::npos;
  std::string *key_id= key->get_key_id();

  if ((*key->get_user_id()).empty() != true ||
      (colon_position= key_id->find(':')) == std::string::npos ||
      colon_position == key_id->length() - 1)
    return false;

  system_key_id= key_id->substr(0, colon_position);
  std::string version= key_id->substr(colon_position+1,
                       key_id->length() - colon_position);

  if (str2int(version.c_str(), 10, 0, LONG_MAX, &key_version) == NullS ||
      system_key_id_to_key_id.count(system_key_id) == 0)
    return false;
  return true;
}

void System_keys_container::update_system_key(IKey* key, std::string &system_key_id, long key_version)
{
  if (system_key_id_to_key_id[system_key_id].version < key_version)
  {
    system_key_id_to_key_id[system_key_id].key_id = *(key->get_key_id());
    system_key_id_to_key_id[system_key_id].version = key_version;
  }
}

void System_keys_container::update_if_system_key(IKey *key)
{
  std::string system_key_id;
  long key_version;
  
  if (is_system_key(key, system_key_id, key_version))
    update_system_key(key, system_key_id, key_version);
}

} //namespace keyring
