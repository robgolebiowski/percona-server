#ifndef MYSQL_VAULT_IO_H
#define MYSQL_VAULT_IO_H

#include <my_global.h>
#include <logger.h>
#include "i_keyring_io.h"
#include "vault_keys_list.h"
#include "vault_parser.h"
#include "vault_credentials_parser.h"
#include "vault_curl.h"
#include "vault_key_serializer.h"

namespace keyring {

class Vault_io : public IKeyring_io
{
public:
  Vault_io(ILogger *logger)
    : logger(logger)
    , vault_curl(logger)
  {}

  my_bool retrieve_key_type_and_value(IKey *key);

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
    return FALSE; //move to implementation
  }

protected:
  my_bool write_key(IKey *key);
  my_bool delete_key(IKey *key);
  my_bool check_for_errors_in_response_and_log(std::string *json_response);

  ILogger *logger;
  Vault_parser vault_parser;
  Vault_curl vault_curl;
  Vault_key_serializer vault_key_serializer;
};

} //namespace keyring

#endif //MYSQL_VAULT_IO_H
