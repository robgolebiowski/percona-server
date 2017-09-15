#ifndef SYSTEM_KEYS_CONTAINER_INCLUDED
#define SYSTEM_KEYS_CONTAINER_INCLUDED

#include <my_global.h>
#include "i_system_keys_container.h"
#include <map>
#include <vector>

namespace keyring {

class System_keys_container : public ISystem_keys_container
{
public:
  System_keys_container();
  ~System_keys_container();

  virtual void update_if_system_key(IKey *key);
  virtual IKey* fetch_system_key(IKey *key);

protected:
  struct System_key_data
  {
    System_key_data()
      : version(0),
        key(NULL)
    {}
    long version;
    IKey *key;
  };
  struct System_key
  {
    std::string id;
    System_key_data data;
  };

  bool is_system_key(IKey *key, System_key &system_key);
  void update_system_key(System_key& system_key);
  IKey* get_system_key_from_map(std::string key_id);

private:
  std::map<std::string, System_key> system_key_id_data;
  std::vector<IKey*> keys_allocated_by_us;
};

} //namespace keyring

#endif //SYSTEM_KEYS_CONTAINER_INCLUDED
