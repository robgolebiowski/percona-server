#ifndef MYSQL_I_SYSTEM_KEYS_CONTAINER_H
#define MYSQL_I_SYSTEM_KEYS_CONTAINER_H

#include <my_global.h>
#include "i_keyring_key.h"

namespace keyring
{
  class ISystem_keys_container : public Keyring_alloc
  {
  public:
    virtual IKey* get_latest_key_if_system_key(IKey *key) = 0;
    virtual void store_or_update_if_system_key(IKey *key) = 0;
    virtual bool rotate_key_id_if_existing_system_key(IKey *key) = 0;
    virtual bool is_system_key(IKey *key) = 0;

    virtual ~ISystem_keys_container()
    {}
  };
} //namespace keyring

#endif //MYSQL_I_SYSTEM_KEYS_CONTAINER_H
