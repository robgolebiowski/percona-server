//
// Created by rob on 03.03.17.
//

#ifndef MYSQL_VAULT_KEYS_CONTAINER_H
#define MYSQL_VAULT_KEYS_CONTAINER_H

#include "keys_container.h"
#include "vault_io.h"

namespace keyring
{

class Vault_keys_container : public Keys_container
{
public:
  Vault_keys_container(ILogger* logger)
    : Keys_container(logger)
  {}

  virtual IKey* fetch_key(IKey *key);
protected:
  Vault_io *vault_io;
};


}



#endif //MYSQL_VAULT_KEYS_CONTAINER_H
