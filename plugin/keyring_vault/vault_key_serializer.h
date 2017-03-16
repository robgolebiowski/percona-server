//
// Created by rob on 02.03.17.
//

#include "i_serializer.h"
#include "vault_key.h"

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
    DBUG_ASSERT(vault_key != NULL);
    vault_key->set_key_operation(operation);

    return new Vault_key(*vault_key);

    /*
    Vault_keys_list *keys_list = new Vault_keys_list();
    Vault_key* vault_key_copy = new Vault_key(*vault_key);
    vault_key_copy->set_key_operation(operation);
    keys_list->push_back(vault_key_copy);
    return vault_key_copy;*/
  }
};

}

#endif //MYSQL_VAULT_KEY_SERIALIZER_H
