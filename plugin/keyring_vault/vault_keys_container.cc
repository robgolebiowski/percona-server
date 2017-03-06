//
// Created by rob on 03.03.17.
//

#include <my_global.h>
#include "vault_keys_container.h"

namespace keyring
{
  IKey* Vault_keys_container::fetch_key(IKey *key)
  {
    DBUG_ASSERT(key->get_key_data() == NULL);
    DBUG_ASSERT(key->get_key_type()->empty());

    IKey *fetched_key= get_key_from_hash(key);

    if(fetched_key->get_key_type() == NULL &&
       vault_io->retrieve_key_type_and_value(fetched_key)) //key is fetched for the first time
      return NULL; //add a logger - or better error will be comming from vault_io

    return Keys_container::fetch_key(key);
  }
}
