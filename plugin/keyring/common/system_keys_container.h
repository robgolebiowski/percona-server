#ifndef SYSTEM_KEYS_CONTAINER_INCLUDED
#define SYSTEM_KEYS_CONTAINER_INCLUDED

#include <my_global.h>
#include "i_system_keys_container.h"
#include <map>

namespace keyring {

class System_keys_container : public ISystem_keys_container
{
public:
  System_keys_container();

  virtual std::string get_latest_key_id_version_if_system_key(IKey *key);
  virtual void update_if_system_key(IKey *key);
  virtual bool get_key_with_rotated_id_if_system_key(IKey *key);
  virtual bool is_system_key(IKey *key);

protected:
  bool parse_key_id(std::string &key_id, std::string &system_key_id, long &key_version);
  void update_system_key(IKey* key, std::string &system_key_id, long key_version);
  bool is_system_key_with_version(IKey *key, std::string &system_key_id, long &key_version);

private:
  struct KeyIdAndVersion
  {
    KeyIdAndVersion()
    {}

    KeyIdAndVersion(std::string key_id, long version)
      : key_id(key_id)
      , version(version)
    {}

    std::string key_id;
    long version;
  };

  std::map<std::string, KeyIdAndVersion> system_key_id_to_key_id;
};

} //namespace keyring

#endif //SYSTEM_KEYS_CONTAINER_INCLUDED
