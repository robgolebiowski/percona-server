#include "vault_credentials.h"

namespace keyring
{

static Secure_string empty_value;

const Secure_string& get_credential(const Vault_credentials &credentials, const Secure_string &key)
{
  std::map<Secure_string, Secure_string>::const_iterator it =
    credentials.find(key);
  if (it == credentials.end())
    return empty_value;
  else 
    return it->second;
}

}

