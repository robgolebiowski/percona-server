#ifndef MYSQL_I_SYSTEM_KEYS_CONTAINER_H
#define MYSQL_I_SYSTEM_KEYS_CONTAINER_H

#include <my_global.h>
#include "i_keyring_key.h"

namespace keyring
{
  class ISystem_keys_container : public Keyring_alloc
  {
  public:
    virtual std::string get_latest_key_id_version_if_system_key(IKey *key) = 0;
    virtual void update_if_system_key(IKey *key) = 0;
    virtual bool get_key_with_rotated_id_if_system_key(IKey *key) = 0;
    virtual bool is_system_key(IKey *key) = 0;

    virtual ~ISystem_keys_container()
    {}
  };
} //namespace keyring

#endif //MYSQL_I_SYSTEM_KEYS_CONTAINER_H
