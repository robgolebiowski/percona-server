//
// Created by rob on 03.03.17.
//

#ifndef MYSQL_VAULT_CURL_H
#define MYSQL_VAULT_CURL_H

#include <my_global.h>
#include <curl/curl.h>
#include "logger.h"
#include "i_keyring_key.h"

namespace keyring
{

class Vault_curl
{
public:
  Vault_curl(ILogger *logger)
    : logger(logger)
    , list(NULL)
  {}

  ~Vault_curl()
  {
    if (list != NULL)
      curl_slist_free_all(list);
  }

  my_bool init(std::string *vault_url, std::string *auth_token);
  my_bool list_keys(std::string *response);
  my_bool write_key(IKey *key, std::string *response);
  my_bool read_key(IKey *key, std::string *response);
  my_bool delete_key(IKey *key, std::string *response);

protected:
  my_bool reset_curl_session();

  ILogger *logger;
  std::string token_header;
  std::string vault_url;
  CURL *curl;
  std::stringstream read_data_ss;
  struct curl_slist *list;
};

}

#endif //MYSQL_VAULT_CURL_H
