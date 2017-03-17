//
// Created by rob on 08.03.17.
//

#include <my_global.h>
#include "vault_credentials_parser.h"
#include <fstream>
#include <algorithm>
#include <iostream>

namespace keyring
{
  struct Is_space
  {
    my_bool operator()(char c)
    {
      return std::isspace(c);
    }
  };

  SecureString* Vault_credentials_parser::get_value_for_option(SecureString *option, Vault_credentials *vault_credentials)
  {
    if (*option == "vault_url")
      return &vault_credentials->vault_url;
    else if (*option == "secret_mount_point")
      return &vault_credentials->secret_mount_point;
    else if (*option == "token")
      return &vault_credentials->token;
    return NULL;
  }

  my_bool Vault_credentials_parser::parse_line(uint line_number, SecureString *line, Vault_credentials *vault_credentials)
  {
    if (line->empty())
      return FALSE;

    size_t eq_sign_pos = line->find('=');
    std::stringstream err_ss;

    if (eq_sign_pos == std::string::npos)
    {
      err_ss << "Could not parse credential file. Cannot find equal sign (=) in line: ";
      err_ss << line_number << '.';

      logger->log(MY_ERROR_LEVEL, err_ss.str().c_str());
      return TRUE;
    }
    SecureString option = line->substr(0, eq_sign_pos); //TODO:Should not SecureString be called Secure_string
    option.erase(std::remove_if(option.begin(), option.end(), Is_space()), option.end());

    SecureString *value = get_value_for_option(&option, vault_credentials);

    if (value == NULL)
    {
      err_ss <<  "Could not parse credential file. Unknown option \"" << option << "\" in line: ";
      err_ss << line_number << '.';
      return TRUE;
    }

    if (value->empty() == false) //repeated option in file
    {
      err_ss << "Could not parse credential file. Seems that value for option " << option;
      err_ss << " has been specified more than once in line: " << line_number << '.';

      logger->log(MY_ERROR_LEVEL, err_ss.str().c_str());
      return TRUE;
    }
    value->erase(std::remove_if(value->begin(), value->end(), Is_space()), value->end());

    if (value->empty())
    {
      err_ss << "Could not parse credential file. Seems there is no value specified ";
      err_ss << "for option " << option << " in line: " << line_number << '.';

      logger->log(MY_ERROR_LEVEL, err_ss.str().c_str());
      return TRUE;
    }
    return FALSE;
  }

  my_bool Vault_credentials_parser::parse(std::string *file_url, Vault_credentials *vault_credentials)
  {
    Vault_credentials vault_credentials_in_progress;
    std::ifstream credentials_file(file_url->c_str());
    if (!credentials_file)
    {
      logger->log(MY_ERROR_LEVEL, "Could not open file with credentials.");
      //token->clear();
      return TRUE;
    }
    uint line_number = 1;
    SecureString line;
    while(getline(credentials_file, line).fail() == false)
      if(parse_line(line_number, &line, &vault_credentials_in_progress))
      {
        line_number++;
        return TRUE;
      }

    //TODO: Refactor this ?
    if (vault_credentials_in_progress.vault_url.empty())
    {
      logger->log(MY_ERROR_LEVEL, "Could not read vault_url from the configuration file");
      return TRUE;
    }
    if (vault_credentials_in_progress.secret_mount_point.empty())
    {
      logger->log(MY_ERROR_LEVEL, "Could not read secret_mount_point from the configuration file"); //TODO: Should I change secret_mount_point to generic_mount_point?
      return TRUE;
    }
    if (vault_credentials_in_progress.token.empty())
    {
      logger->log(MY_ERROR_LEVEL, "Could not read token from the configuration file");
      return TRUE;
    }
   

    /*
    if(getline(credentials_file, *token).fail() || token->empty() ||
       token->find_first_of(" \t") != std::string::npos)
    {
      logger->log(MY_ERROR_LEVEL, "Could not read token from credential file.");
      token->clear();
      return TRUE;
    }*/
    *vault_credentials = vault_credentials_in_progress;
    return FALSE;
  }
  
}
