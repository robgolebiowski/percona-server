//
// Created by rob on 24.02.17.
//

#include "keyring_key.h"

#ifndef MYSQL_VAULT_KEY_H
#define MYSQL_VAULT_KEY_H

namespace keyring {

struct Vault_key : public Key
{
  virtual void create_key_signature() const;
  void xor_data()
  {
      /*We do not xor data in keyring_vault */
  }
};

} //namespace keyring


#endif //MYSQL_VAULT_KEY_H
