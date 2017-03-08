//
// Created by rob on 08.03.17.
//

#include <my_global.h>
#include "vault_credentials_parser.h"
#include <fstream>
#include <iostream>

namespace keyring
{
  my_bool Vault_credentials_parser::parse(std::string *file_url, std::string *token)
  {
    std::ifstream credentials_file(file_url->c_str());
    if (!credentials_file)
    {
      logger->log(MY_ERROR_LEVEL, "Could not open file with credentials.");
      token->clear();
      return TRUE;
    }
    if(getline(credentials_file, *token).fail() || token->empty() ||
       token->find_first_of(" \t") != std::string::npos)
    {
      logger->log(MY_ERROR_LEVEL, "Could not read token from credential file.");
      token->clear();
      return TRUE;
    }
    return FALSE;
  }
}