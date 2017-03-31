#ifndef MYSQL_VAULT_IO_H
#define MYSQL_VAULT_IO_H

#include <my_global.h>
#include <logger.h>
#include "i_vault_io.h"
#include "vault_keys_list.h"
#include "vault_parser.h"
#include "vault_credentials_parser.h"
#include "vault_curl.h"
#include "vault_key_serializer.h"

namespace keyring {

class Vault_io : public IVault_io
{
public:
  Vault_io(ILogger *logger, IVault_curl *vault_curl,
           IVault_parser *vault_parser)
    : logger(logger)
    , vault_curl(vault_curl)
    , vault_parser(vault_parser)
  {}

  ~Vault_io();

  virtual my_bool retrieve_key_type_and_data(IKey *key);

  virtual my_bool init(std::string *keyring_storage_url);
  virtual my_bool flush_to_backup(ISerialized_object *serialized_object)
  {
    return FALSE; //we do not have backup storage in vault
  }
  virtual my_bool flush_to_storage(ISerialized_object *serialized_object);

  virtual ISerializer *get_serializer();
  virtual my_bool get_serialized_object(ISerialized_object **serialized_object);
  virtual my_bool has_next_serialized_object()
  {
    return FALSE;
  }

protected:
  my_bool write_key(IKey *key);
  my_bool delete_key(IKey *key);
  std::string get_errors_from_response(std::string *json_response);

  ILogger *logger;
  IVault_curl *vault_curl;
  IVault_parser *vault_parser;
  Vault_key_serializer vault_key_serializer;
};

} //namespace keyring

#endif //MYSQL_VAULT_IO_H
