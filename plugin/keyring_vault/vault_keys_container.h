#ifndef MYSQL_VAULT_KEYS_CONTAINER_H
#define MYSQL_VAULT_KEYS_CONTAINER_H

#include "keys_container.h"
#include "i_vault_io.h"

namespace keyring
{

class Vault_keys_container : public Keys_container
{
public:
  Vault_keys_container(ILogger* logger)
    : Keys_container(logger)
  {}

  my_bool init(IKeyring_io* keyring_io, std::string keyring_storage_url);
  virtual IKey* fetch_key(IKey *key);

protected:
  virtual my_bool flush_to_backup();
  IVault_io *vault_io;
};

} //namespace keyring

#endif //MYSQL_VAULT_KEYS_CONTAINER_H
