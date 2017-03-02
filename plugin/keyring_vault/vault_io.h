#ifndef MYSQL_VAULT_IO_H
#define MYSQL_VAULT_IO_H

#include <my_global.h>
#include <logger.h>
#include "i_keyring_io.h"
#include "vault_keys_list.h"
#include "vault_parser.h"
#include "vault_key_serializer.h"

namespace keyring {

class Vault_io : public IKeyring_io
{
public:
  Vault_io(ILogger *logger)
    : logger(logger)
  {}

  my_bool retrieve_key_type_and_value(Vault_key *key);

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
    return FALSE; //not implemented yet
  }

private:
  ILogger *logger;
  Vault_parser vault_parser;
  std::string json_response;
  Vault_key_serializer vault_key_serializer;
//  typedef std::list<IKey*> Keys_list;
//  Keys_list keys;
//  size_t keys_pod_size;
};

} //namespace keyring

#endif //MYSQL_VAULT_IO_H
