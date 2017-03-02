//
// Created by rob on 24.02.17.
//

#include "keyring_key.h"
#include "i_serialized_object.h"

#ifndef MYSQL_VAULT_KEY_H
#define MYSQL_VAULT_KEY_H

namespace keyring {

struct Vault_key : public Key, ISerialized_object
{
  Vault_key(const char *a_key_id, const char *a_key_type, const char *a_user_id,
      const void *a_key, size_t a_key_len)
    : Key(a_key_id, a_key_type, a_user_id, a_key, a_key_len)
  {}

  //Vault_key is itself a serialized_object but we will not need
  //get_next_key, has_next_key so making them no-ops;
  virtual my_bool get_next_key(IKey **key)
  {
    return TRUE;
  }
  virtual my_bool has_next_key()
  {
    return FALSE;
  }
  virtual void create_key_signature() const;
  void xor_data()
  {
      /*We do not xor data in keyring_vault */
  }
};

} //namespace keyring


#endif //MYSQL_VAULT_KEY_H
