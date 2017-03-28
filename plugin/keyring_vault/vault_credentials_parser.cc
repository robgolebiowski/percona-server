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
  struct Is_not_space
  {
    my_bool operator()(char c)
    {
      return !std::isspace(c);
    }
  };

  static inline SecureString* ltrim(SecureString *s) {
      s->erase(s->begin(), std::find_if(s->begin(), s->end(),
              Is_not_space()));
      return s;
  }

  // trim from end
  static inline SecureString* rtrim(SecureString *s) {
      s->erase(std::find_if(s->rbegin(), s->rend(),
               Is_not_space()).base(), s->end());
      return s;
  }

  // trim from both ends
  static inline SecureString* trim(SecureString *s) {
      return ltrim(rtrim(s));
  }

  void Vault_credentials_parser::reset_vault_credentials(Vault_credentials *vault_credentials)
  {
    for(Vault_credentials::iterator iter = vault_credentials->begin();
        iter != vault_credentials->end(); ++iter)
      iter->second.clear();
  }

  my_bool Vault_credentials_parser::is_valid_option(SecureString *option)
  {
    return vault_credentials_in_progress.count(*option);
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
    trim(&option); 

    if (is_valid_option(&option) == false)
    {
      err_ss << "Could not parse credential file. Unknown option \"" << option << "\" in line: ";
      err_ss << line_number << '.';
      return TRUE;
    }
    SecureString *value = &(*vault_credentials)[option];

    if (value->empty() == false) //repeated option in file
    {
      err_ss << "Could not parse credential file. Seems that value for option " << option;
      err_ss << " has been specified more than once in line: " << line_number << '.';
      logger->log(MY_ERROR_LEVEL, err_ss.str().c_str());
      return TRUE;
    }
    *value = line->substr(eq_sign_pos + 1, line->size() - (eq_sign_pos + 1)); 
    trim(value);

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
    reset_vault_credentials(&vault_credentials_in_progress);

    std::ifstream credentials_file(file_url->c_str());
    if (!credentials_file)
    {
      logger->log(MY_ERROR_LEVEL, "Could not open file with credentials.");
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

    for(Vault_credentials::const_iterator iter = vault_credentials_in_progress.begin();
        iter != vault_credentials_in_progress.end(); ++iter)
    {
      if (iter->second.empty() && optional_value.count(iter->first) == 0)
      {
        std::stringstream err_ss;
        err_ss << "Could not read " << iter->first << " from the configuration file.";
        logger->log(MY_ERROR_LEVEL, err_ss.str().c_str());
        return TRUE;
      }
    }
    *vault_credentials = vault_credentials_in_progress;
    return FALSE;
  }
  
}
