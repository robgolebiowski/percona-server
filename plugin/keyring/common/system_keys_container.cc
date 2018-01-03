#include "system_keys_container.h"
#include <climits>

namespace keyring {

const std::string System_keys_container::system_key_prefix = "percona_";

//System_keys_container::System_keys_container()
//{
  //System_key_adapter *percona_binlog_key = new System_key_adapter; 
  //system_key_id_to_system_key.insert(std::make_pair<std::string, System_key_adapter*>("percona_binlog", percona_binlog_key));
//}

System_keys_container::~System_keys_container()
{
  for(System_key_id_to_system_key::iterator iter = system_key_id_to_system_key.begin();
      iter != system_key_id_to_system_key.end();
      ++iter)
    delete iter->second;
}

bool System_keys_container::is_system_key(IKey *key)
{
  std::string system_key_id;
  long key_version;

  return is_system_key_with_version(key, system_key_id, key_version) ||
         is_system_key_without_version(key);
}


IKey* System_keys_container::get_latest_key_if_system_key(IKey *key)
{
  std::string *key_id = key->get_key_id();
  return (key->get_user_id()->empty() == false || system_key_id_to_system_key.count(*key_id) == 0)
         ? NULL
         : system_key_id_to_system_key[*key_id];
}

//std::string System_keys_container::get_latest_key_id_version_if_system_key(IKey *key)
//{
  //std::string *key_id = key->get_key_id();
  //return key->get_user_id()->empty() == false || system_key_id_to_key_id.count(*key_id) == 0 ?
         //"" : system_key_id_to_key_id[*key_id].key_id;
//}

bool System_keys_container::parse_key_id(std::string &key_id, std::string &system_key_id, long &key_version)
{
  std::size_t colon_position = std::string::npos;

  //if ((colon_position = key_id.find(':')) == std::string::npos ||
  if ((colon_position = key_id.find_last_of(':')) == std::string::npos ||
      colon_position == key_id.length() - 1)
    return true;

  system_key_id = key_id.substr(0, colon_position);
  std::string version = key_id.substr(colon_position+1,
                                      key_id.length() - colon_position);

  return str2int(version.c_str(), 10, 0, LONG_MAX, &key_version) == NullS;
}

bool System_keys_container::is_system_key_without_version(IKey *key)
{
  return key->get_user_id()->empty() &&
         key->get_key_id()->compare(0, system_key_prefix.length(),
                                    system_key_prefix) == 0;
         //TODO: Tutaj dodać czy nie ma później dwukropka - w sensie czy to jest system key bez wersji ?
         //system_key_id_to_system_key.count(*key->get_key_id());
}

bool System_keys_container::is_system_key_with_version(IKey *key, std::string &system_key_id, long &key_version)
{
  //std::size_t colon_position= std::string::npos;
  std::string *key_id = key->get_key_id();

  if (key->get_user_id()->empty() == false ||
      parse_key_id(*key_id, system_key_id, key_version) ||
      key->get_key_id()->compare(0, system_key_prefix.length(),
                                    system_key_prefix) != 0)
    return false;
  
  //if ((*key->get_user_id()).empty() != true ||
      //(colon_position= key_id->find(':')) == std::string::npos ||
      //colon_position == key_id->length() - 1)
    //return false;

  //system_key_id= key_id->substr(0, colon_position);
  //std::string version= key_id->substr(colon_position+1,
                       //key_id->length() - colon_position);

  //if (str2int(version.c_str(), 10, 0, LONG_MAX, &key_version) == NullS ||
      //system_key_id_to_key_id.count(system_key_id) == 0)
    //return false;
  return true;
}

void System_keys_container::store_or_update_system_key(IKey* key, std::string &system_key_id, long key_version)
{
  if (system_key_id_to_system_key.count(system_key_id) == 0)
    system_key_id_to_system_key.insert(std::make_pair<std::string, System_key_adapter*>(system_key_id, new System_key_adapter(key_version, key)));
  else
    update_system_key(key, system_key_id, key_version);
}

void System_keys_container::update_system_key(IKey* key, std::string &system_key_id, long key_version)
{
  //if (system_key_id_to_system_key.count(system_key_id) == 0)
    //system_key_id_to_system_key.insert(std::make_pair<std::string, System_key_adapter*>(system_key_id, new System_key_adapter));

  if (system_key_id_to_system_key[system_key_id]->get_key_version() < key_version)
    system_key_id_to_system_key[system_key_id]->set_keyring_key(key, key_version);
}

template <long N> struct NumberOfDigits 
{
  enum { value = 1 + NumberOfDigits<N/10>::value };
};

template <> struct NumberOfDigits<0>
{
  enum { value = 1 };
};

bool System_keys_container::rotate_key_id_if_existing_system_key(IKey *key)
{
  if (is_system_key_without_version(key) == false ||
      system_key_id_to_system_key.count(*key->get_key_id()) == 0)
    return false;

  long key_version = system_key_id_to_system_key[*key->get_key_id()]->get_key_version();

  if (key_version == LONG_MAX)
  {
    //log_error, that max version has been reached
    return true;
  }
  key_version++;

  std::ostringstream system_key_id_with_inc_version_ss;
  system_key_id_with_inc_version_ss << *key->get_key_id() << ':';
  system_key_id_with_inc_version_ss << key_version;

  *(key->get_key_id()) = system_key_id_with_inc_version_ss.str();
  return false;
}

//void System_keys_container::update_if_system_key(IKey *key)
void System_keys_container::store_or_update_if_system_key(IKey *key)
{
  std::string system_key_id;
  long key_version;

  if (is_system_key_with_version(key, system_key_id, key_version))
    store_or_update_system_key(key, system_key_id, key_version);
  else if (is_system_key_without_version(key))
    store_or_update_system_key(key, *key->get_key_id(), 0);
}

} //namespace keyring
