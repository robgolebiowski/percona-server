#include <my_global.h>
#include "vault_io.h"
#include <curl/curl.h>
#include <sstream>

namespace keyring {

my_bool Vault_io::init(std::string *keyring_storage_url)
{
  std::string url = "http://127.0.0.1:8200";
  std::string token;

  Vault_credentials_parser vault_credentials_parser(logger);
  if (vault_credentials_parser.parse(keyring_storage_url, &token))
    return TRUE;

  return vault_curl.init(&url, &token);
}

my_bool Vault_io::check_for_errors_in_response_and_log(std::string *json_response)
{
  std::string errors;

  if(vault_parser.parse_errors(json_response, &errors))
  {
    logger->log(MY_ERROR_LEVEL, "Error while parsing error messages");
    return TRUE;
  }
  if (errors.size()) //we found error in response
  {
    logger->log(MY_ERROR_LEVEL, ("Vault has returned the following errors: "
                                + errors).c_str());
    return TRUE;
  }
  return FALSE;
}

my_bool Vault_io::get_serialized_object(ISerialized_object **serialized_object)
{
  *serialized_object= NULL;
  std::string json_response;

  if(vault_curl.list_keys(&json_response))
    return TRUE;

  Vault_keys_list *keys = new Vault_keys_list();

  if (vault_parser.parse_keys(&json_response, keys) ||
      check_for_errors_in_response_and_log(&json_response))
  {
    delete keys;
    return TRUE;
  }

  if (keys->size() == 0)
  {
    delete keys;
    keys= NULL;
  }

  *serialized_object = keys;
  return FALSE;
}

my_bool Vault_io::retrieve_key_type_and_value(IKey *key) //TODO:Change value to data
{
  std::string json_response;
  return vault_curl.read_key(key, &json_response) ||
         vault_parser.parse_key_data(&json_response, key);
}

ISerializer* Vault_io::get_serializer()
{
  return &vault_key_serializer;
}

my_bool Vault_io::write_key(IKey *key)
{
  std::string json_response;
  return vault_curl.write_key(key, &json_response);
}

my_bool Vault_io::delete_key(IKey *key)
{
  std::string json_response;
  return vault_curl.delete_key(key, &json_response);
}

my_bool Vault_io::flush_to_storage(ISerialized_object *serialized_object)
{
  DBUG_ASSERT(serialized_object->has_next_key() == TRUE);
  IKey *vault_key;

  my_bool was_error= serialized_object->get_next_key(&vault_key) ||
                     vault_key == NULL ||
                     serialized_object->get_key_operation() == STORE_KEY
                       ? write_key(vault_key)
                       : delete_key(vault_key);
  delete vault_key;
  return was_error;
}

} //namespace keyring






























