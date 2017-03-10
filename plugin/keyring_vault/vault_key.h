//
// Created by rob on 24.02.17.
//

#include "keyring_key.h"
#include "i_serialized_object.h"

#ifndef MYSQL_VAULT_KEY_H
#define MYSQL_VAULT_KEY_H

namespace keyring {

struct Vault_key : public Key, public ISerialized_object
{
  Vault_key(const char *a_key_id, const char *a_key_type, const char *a_user_id,
      const void *a_key, size_t a_key_len)
    : Key(a_key_id, a_key_type, a_user_id, a_key, a_key_len)
    , was_key_retrieved(FALSE)	
  {}

  Vault_key(const Vault_key &vault_key)
    : Key(vault_key.key_id.c_str(), vault_key.key_type.c_str(),
          vault_key.user_id.c_str(), vault_key.key.get(), vault_key.key_len)
  {
    this->key_operation = vault_key.key_operation;
    this->was_key_retrieved = vault_key.was_key_retrieved;
  }

  Vault_key()
  {}

  //Vault_key is itself a serialized_object but we will not need
  //get_next_key, has_next_key so making them no-ops;
  virtual my_bool get_next_key(IKey **key)
  {
    if (was_key_retrieved)
    {
      *key = NULL;
      return TRUE;
    }
    *key = new Vault_key(*this);	  
    return FALSE;
  }
  virtual my_bool has_next_key()
  {
    return !was_key_retrieved;	  
  }
  virtual void create_key_signature() const;
  void xor_data()
  {
      /*We do not xor data in keyring_vault */
  }
  protected:
  my_bool was_key_retrieved;

};

} //namespace keyring


#endif //MYSQL_VAULT_KEY_H
