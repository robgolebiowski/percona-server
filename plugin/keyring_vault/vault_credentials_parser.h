//
// Created by rob on 08.03.17.
//

#ifndef MYSQL_VAULT_CREDENTIALS_PARSER_H
#define MYSQL_VAULT_CREDENTIALS_PARSER_H

#include <my_global.h>
#include <string>
#include "logger.h"

namespace keyring
{
  class Vault_credentials_parser
  {
  public:
    Vault_credentials_parser(ILogger *logger)
      : logger(logger)
    {}

    my_bool parse(std::string *file_url, std::string *token);

  protected:
    ILogger *logger;

  };

} //namespace keyring

#endif //MYSQL_VAULT_CREDENTIALS_PARSER_H
