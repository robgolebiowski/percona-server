//
// Created by rob on 24.02.17.
//

#include "keyring_key.h"

#ifndef MYSQL_VAULT_KEY_H
#define MYSQL_VAULT_KEY_H

namespace keyring {

struct Vault_key : public Key
{
  Vault_key(const char *a_key_id, const char *a_key_type, const char *a_user_id,
      const void *a_key, size_t a_key_len)
    : Key(a_key_id, a_key_type, a_user_id, a_key, a_key_len)
  {}

//  virtual void create_key_signature() const;
  void xor_data()
  {
      /*We do not xor data in keyring_vault */
  }
};

} //namespace keyring


#endif //MYSQL_VAULT_KEY_H
