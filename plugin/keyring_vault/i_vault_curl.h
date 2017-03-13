#ifndef MYSQL_I_VAULT_CURL
#define MYSQL_I_VAULT_CURL

#include "i_keyring_key.h"
#include "i_keyring_io.h"

namespace keyring {

class IVault_curl : public Keyring_alloc
{
public:
  virtual my_bool init(std::string *vault_url, std::string *auth_token) = 0;
  virtual my_bool list_keys(std::string *response) = 0;
  virtual my_bool write_key(IKey *key, std::string *response) = 0;
  virtual my_bool read_key(IKey *key, std::string *response) = 0;
  virtual my_bool delete_key(IKey *key, std::string *response) = 0;

  virtual ~IVault_curl() {};
};

}//namespace keyring

#endif //MYSQL_I_KEYS_CONTAINER_H
