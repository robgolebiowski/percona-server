//
// Created by rob on 01.03.17.
//

#include "vault_keys_list.h"

namespace keyring
{

my_bool Vault_keys_list::get_next_key(IKey **key)
{
  *key= NULL;
  if (keys_iter == keys.end())
    return TRUE;
  *key = *(keys_iter++);
  return FALSE;
}

my_bool Vault_keys_list::has_next_key()
{
  return keys_iter != keys.end();
}

size_t Vault_keys_list::size()
{
  return keys.size();
}

Vault_keys_list::~Vault_keys_list()
{
  //remove not fetched keys
  while(keys_iter != keys.end())
    delete *keys_iter;
}

void Vault_keys_list::push_back(IKey* key)
{
  keys.push_back(key);
  if(keys.size() == 0)
    keys_iter = keys.begin();
}

} //namespace keyring