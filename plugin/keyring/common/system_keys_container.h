#ifndef SYSTEM_KEYS_CONTAINER_INCLUDED
#define SYSTEM_KEYS_CONTAINER_INCLUDED

#include <my_global.h>
#include "i_system_keys_container.h"
#include "system_key.h"
#include <map>

namespace keyring {

class System_keys_container : public ISystem_keys_container
{
public:
  System_keys_container();
  ~System_keys_container();

  IKey* get_latest_key_if_system_key(IKey *key);
  //virtual std::string get_latest_key_id_version_if_system_key(IKey *key);
  virtual void update_if_system_key(IKey *key);
  virtual void rotate_key_id_if_system_key(IKey *key);
  virtual bool is_system_key(IKey *key);

protected:
  bool parse_key_id(std::string &key_id, std::string &system_key_id, long &key_version);
  void update_system_key(IKey* key, std::string &system_key_id, long key_version);
  bool is_system_key_with_version(IKey *key, std::string &system_key_id, long &key_version);
  bool is_system_key_without_version(IKey *key);

private:
  typedef std::map<std::string, System_key_adapter*> System_key_id_to_system_key;
  System_key_id_to_system_key system_key_id_to_system_key;
};

} //namespace keyring

#endif //SYSTEM_KEYS_CONTAINER_INCLUDED
