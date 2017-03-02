//
// Created by rob on 24.02.17.
//

#include "vault_key.h"
#include <sstream>

namespace keyring {

void Vault_key::create_key_signature() const
{
  if (key_id.empty())
    return;
  std::stringstream key_signature_ss;
  key_signature_ss << key_id.length();
  key_signature_ss << key_id;
  key_signature_ss << user_id.length();
  key_signature_ss << user_id;
  key_signature = key_signature_ss.str();
}

} //namespace keyring

