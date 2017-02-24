#ifndef MYSQL_VAULT_IO_H
#define MYSQL_VAULT_IO_H

#include <my_global.h>
#include <logger.h>
#include "i_keyring_io.h"

namespace keyring {

class Vault_io : public IKeyring_io
{
public:
  Vault_io(ILogger *logger)
    : logger(logger)
  {}

  virtual my_bool init(std::string *keyring_storage_url);
  virtual my_bool flush_to_backup(ISerialized_object *serialized_object)
  {
    return FALSE; //we do not have backup storage in vault
  }
  virtual my_bool flush_to_storage(ISerialized_object *serialized_object)
  {
    return FALSE; //not implemented yet
  }

  virtual ISerializer *get_serializer()
  {
    return FALSE; //not implemented yet
  }
  virtual my_bool get_serialized_object(ISerialized_object **serialized_object)
  {
    return FALSE; //not implemented yet
  }
  virtual my_bool has_next_serialized_object()
  {
    return FALSE; //not implemented yet
  }

private:
  ILogger *logger;
};

} //namespace keyring

#endif //MYSQL_VAULT_IO_H
