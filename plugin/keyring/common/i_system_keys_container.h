#ifndef MYSQL_I_SYSTEM_KEYS_CONTAINER_H
#define MYSQL_I_SYSTEM_KEYS_CONTAINER_H

#include <my_global.h>
#include "i_keyring_key.h"

namespace keyring
{
  class ISystem_keys_container : public Keyring_alloc
  {
  public:
    /**
     * This function adds/updates key in system_keys_container
     * if key provided by the key argument is a system_key
    */ 
    virtual void update_if_system_key(IKey *key) = 0;
    virtual IKey* fetch_system_key(IKey *key) = 0;
    virtual ~ISystem_keys_container()
    {}
  };
} //namespace keyring

#endif //MYSQL_I_SYSTEM_KEYS_CONTAINER_H
