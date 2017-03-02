//
// Created by rob on 02.03.17.
//

#include "i_serializer.h"

#ifndef MYSQL_VAULT_KEY_SERIALIZER_H
#define MYSQL_VAULT_KEY_SERIALIZER_H

namespace keyring
{

class Vault_key_serializer :  public ISerializer
{
public:
  ISerialized_object* serialize(HASH *keys_hash, IKey *key,
                                const Key_operation operation)
  {
    Vault_key* vault_key = dynamic_cast<Vault_key*>(key);
    if (vault_key == NULL)
      return NULL;
    vault_key->set_key_operation(operation);
    return vault_key;
  }
};

}

#endif //MYSQL_VAULT_KEY_SERIALIZER_H
