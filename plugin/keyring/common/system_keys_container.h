#ifndef SYSTEM_KEYS_CONTAINER_INCLUDED
#define SYSTEM_KEYS_CONTAINER_INCLUDED

#include <my_global.h>
#include <boost/move/unique_ptr.hpp>
#include <map>
#include "i_system_keys_container.h"
#include "system_key_adapter.h"
#include "logger.h"

namespace keyring {

// System_keys_container stores system keys together with links to their latest versions.
// Latest version of a key itself is stored somewhere else (pressumably in keys_container).
// For instance system_keys_container maps percona_binlog to its latest version percona_binlog:12,
// the key percona_binlog:12 itself is stored in keys_container. System_key_container 
// only maps system key percona_binlog to its latest version, i.e. percona_binlog:12,
// it does not know about other versions of the key. The keys returned by System_keys_container
// are encapsulated in System_key_adapter which allows to retrieve information like key's
// version.
class System_keys_container : public ISystem_keys_container
{
public:
  System_keys_container(ILogger *logger)
    : logger(logger)
  {} 
  ~System_keys_container();

  // Returns key with latest version when called with plain system key (ex. percona_binlog)
  // For instance - when key's (argument key) id is system_key and latest verion of system_key
  // is x it will return key with id system_key:x
  virtual IKey* get_latest_key_if_system_key_without_version(IKey *key);

  // Only system keys with already assigned version can be stored inside system_keys_container
  // for instance : percona_binlog:0
  virtual void store_or_update_if_system_key_with_version(IKey *key);
  
  // Pass key with system_key id (for instance percona_binlog) to get next version of the
  // system_key, for instance : 
  // System_keys_container already has percona_binlog key with version 12 : percona_binlog:12
  // Calling this function will assing percona_binlog:13 as key_id to key passed as argument
  virtual bool rotate_key_id_if_system_key_without_version(IKey *key);

  // Returns true if key id of key argument is either system_key or system_key:x
  // For instance percona_binlog or percona_binlog:12
  virtual bool is_system_key(IKey *key);

private:
  bool parse_system_key_id_with_version(std::string &key_id, std::string &system_key_id, uint &key_version);
  void update_system_key(IKey* key, std::string &system_key_id, uint key_version);
  bool is_system_key_with_version(IKey *key, std::string &system_key_id, uint &key_version);
  bool is_system_key_without_version(IKey *key);

  typedef std::map<std::string, System_key_adapter*> System_key_id_to_system_key;
  System_key_id_to_system_key system_key_id_to_system_key;
  static const std::string system_key_prefix;

  ILogger *logger;
};

} //namespace keyring

#endif //SYSTEM_KEYS_CONTAINER_INCLUDED
