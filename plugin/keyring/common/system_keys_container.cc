#include "system_keys_container.h"

namespace keyring {

//extern PSI_memory_key key_memory_KEYRING;

//uchar *get_hash_system_key(const uchar *key, size_t *length,
                    //my_bool not_used MY_ATTRIBUTE((unused)))
//{
  //std::string *key_signature= &(reinterpret_cast<const System_key*>(key)->id);
  //*length= key_signature->length();
  //return reinterpret_cast<uchar *>(const_cast<char*>(key_signature->c_str()));
//}

//void free_hash_system_key(void* key)
//{
  //IKey *key_to_free= reinterpret_cast<System_key*>(key);
  //delete key_to_free;
//}

//System_keys_container::init()
//{
  //return my_hash_init(system_keys_hash, system_charset_info, 0x100, 0, 0,
                      //(my_hash_get_key) get_hash_system_key, free_hash_system_key,
                      //HASH_UNIQUE, key_memory_KEYRING);
//}

System_keys_container::System_keys_container()
{
  KeyIdAndVersion percona_binlog_key_mock("percona_binlog:-1", -1); 
  system_key_id_to_key_id.insert(std::make_pair("percona_binlog", percona_binlog_key_mock));
}

//System_keys_container::~System_keys_container()
//{
  //for(std::vector<IKey*>::iterator iter = keys_allocated_by_us.begin();
      //iter != keys_allocated_by_us.end(); ++iter)
    //delete *iter;
//}

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

  if (key->get_user_id() != NULL ||
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

//bool System_keys_container::is_system_key(IKey *key, System_key &system_key)
//{
  //std::size_t colon_position= std::string::npos;
  //std::string *key_id= key->get_key_id();

  //if (key->get_user_id() == NULL ||
      //(colon_position= key_id->find(':')) == std::string::npos ||
      //colon_position == key_id->length() - 1)
    //return false;

  //std::string system_key_id= key_id->substr(0, colon_position);
  //std::string key_version= key_id->substr(colon_position+1,
                                          //key_id->length() - colon_position);

  //long version;
  //if (str2int(key_version.c_str(), 10, 0, LONG_MAX, &version) == NullS ||
      //system_key_id_data.count(system_key_id) == 0)
    //return false;

  //system_key.id= system_key_id;
  //system_key.data.key= key;
  //system_key.data.version= version;

  //return true;
//}

//void System_keys_container::update_system_key(System_key& system_key)
//{
  //if (system_key_id_data[system_key.id].data.key == NULL ||
      //system_key_id_data[system_key.id].data.version <
           //system_key.data.version)
    //system_key_id_data[system_key.id].data=
      //system_key.data;
//}

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

//IKey* System_keys_container::fetch_system_key(IKey *key)
//{
  //std::string *key_id = key->get_key_id();
  //if(system_key_id_data.count(*key_id) == 0 || 
     //system_key_id_data[*key_id].data.key == NULL)
    //return NULL;

  //if (*key_id != *system_key_id_data[*key_id].data.key->get_key_id())
  //{
    //IKey *cloned_key= system_key_id_data[*key_id].data.key->clone();
    //*(cloned_key->get_key_id()) = *key_id;
    ////delete system_key_id_data[*key_id].data.key;
    //system_key_id_data[*key_id].data.key = cloned_key;
    //keys_allocated_by_us.push_back(cloned_key);
  //}
  
  //return system_key_id_data[*key_id].data.key;
//}

} //namespace keyring
