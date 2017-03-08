//
// Created by rob on 24.02.17.
//

#ifndef MYSQL_VAULT_PARSER_H
#define MYSQL_VAULT_PARSER_H

#include "my_global.h"
#include "vault_key.h"
#include "vault_keys_list.h"
#include <vector>
#include <algorithm>

namespace keyring
{

//TODO: Add interface
class Vault_parser
{
public:
//    std::string unescape(const std::string& s)
//    {
//      std::string res;
//      std::string::const_iterator it = s.begin();
//      while (it != s.end())
//      {
//        char c = *it++;
//        if (c == '\\' && it != s.end())
//        {
//          switch (*it++) {
//            case '\\': c = ''; break;
//            case 'n': c = '\n'; break;
//            case 't': c = '\t'; break;
//              // all other escapes
//            default:
//              // invalid escape sequence - skip it. alternatively you can copy it as is, throw an exception...
//              continue;
//          }
//        }
//        res += c;
//      }
//
//      return res;
//    }



  my_bool retrieve_list(std::string *payload, std::string list_name, std::string *list)
  {
    std::size_t list_pos = payload->find(list_name);
    if (list_pos == std::string::npos)
    {
      list->clear();
      return FALSE;
    }
    size_t opening_bracket_pos, closing_bracket_pos;

    if ((opening_bracket_pos = payload->find('[', list_pos)) == std::string::npos ||
        (closing_bracket_pos = payload->find(']', opening_bracket_pos)) == std::string::npos)
    {
      list->clear();
      return TRUE;
    }
    *list = payload->substr(opening_bracket_pos,
                            closing_bracket_pos - opening_bracket_pos +1);
    std::remove(list->begin(), list->end(), '\n');
    return FALSE;
  }

  my_bool retrieve_tokens_from_list(std::string *list, std::vector<std::string> *tokens)
  {
    std::size_t token_start = 0, token_end = 0;
//    std::size_t token_end = list_pos+list_name.length() + 1; //move after "list_name"
    while ((token_start = list->find('\"', token_end))
             != std::string::npos &&
           token_start < list->size())
    {
      if ((token_end = list->find('\"', token_start+1)) == std::string::npos)
      {
        //Error, openning " was found, but no closing "
        //TODO:Add logging error
        tokens->clear();
        return TRUE;
      }
      tokens->push_back(list->substr(token_start+1,
                                     token_end-token_start-1));
      ++token_end;
    }

  }

  /*
  my_bool retrieve_tokens_from_list(std::string *payload, std::string list_name, std::vector<std::string> *tokens)
  {
    std::size_t list_pos = payload->find(list_name);
    std::size_t closing_bracket = payload->find('}', list_pos);
    if (list_pos == std::string::npos) //no list found
      return FALSE;
    if (closing_bracket == std::string::npos) //it is illegal for list to have no end
    {
      //TODO: Add logging
      return TRUE;
    }

    std::size_t token_start = 0;
    std::size_t token_end = list_pos+list_name.length() + 1; //move after "list_name"

    while ((token_start = payload->find('\"', token_end+1))
             != std::string::npos &&
           token_start < closing_bracket)
    {
      if ((token_end = payload->find('\"', token_start+1)) == std::string::npos)
      {
        //Error, openning " was found, but no closing "
        //TODO:Add logging error
        tokens->clear();
        return TRUE;
      }
      tokens->push_back(payload->substr(token_start+1,
                                        token_end-token_start-1));
    }
    return FALSE;
  }*/

  my_bool parse_errors(std::string *payload, std::string *errors)
  {
//    return retrieve_tokens_from_list(payload, "errors", error_messages);
    return retrieve_list(payload, "errors", errors);
  }

  my_bool parse_keys(std::string *payload, Vault_keys_list *keys)
  {
    /* payload is build as follows:
     * (...)"data":{"keys":["keysignature","keysignature"]}(...)
     * We need to retrieve keys signatures from it
     */
    std::vector<std::string> key_tokens;
    std::string keys_list;
    if (retrieve_list(payload, "keys", &keys_list) ||
        retrieve_tokens_from_list(&keys_list, &key_tokens))
      return TRUE;

    std::string key_parameters[2];
    for(std::vector<std::string>::const_iterator iter = key_tokens.begin();
        iter != key_tokens.end(); ++iter)
    {
      if (parse_key_signature(&*iter, key_parameters))
        return TRUE;

      IKey *vault_key= new Vault_key(key_parameters[0].c_str(), NULL,
                                     key_parameters[1].c_str(), NULL, 0);
      keys->push_back(vault_key); //TODO: compact new and this call
    }
    return FALSE;
  }

  my_bool parse_key_signature(const std::string *key_signature, std::string key_parameters[2])
  {
    //key_signature= lengthof(key_id)||key_id||lengthof(user_id)||user_id
    std::string digits("0123456789");
    size_t next_pos_to_start_from = 0;
    for (int i= 0; i < 2; ++i)
    {
      std::size_t key_id_pos = key_signature->find_first_not_of(digits, next_pos_to_start_from);
      std::string key_id_length = key_signature->substr(next_pos_to_start_from, key_id_pos);
      int key_l = atoi(key_id_length.c_str());
      key_parameters[i] = key_signature->substr(key_id_pos, key_l);
      next_pos_to_start_from= key_id_pos+key_l;
    }
    return FALSE; //TODO always returns FALSE
  }

  my_bool parse_key_data(std::string *payload, IKey *key)
  {
    std::size_t data_pos = payload->find("data");
    std::size_t closing_bracket = payload->find('}', data_pos);
    if (data_pos == std::string::npos || closing_bracket == std::string::npos) //no keys
      return TRUE; //change to something else? Probably add logger

    size_t type_end = payload->find('\"', data_pos+15);
    std::string type = payload->substr(data_pos+15, (type_end-(data_pos+15)));
    size_t value_end = payload->find('\"', type_end+11);
    std::string value = payload->substr(type_end+11, (value_end-(type_end+11)));
    uchar *data= new uchar[value.length()];
    memcpy(data, value.c_str(), value.length());

    key->set_key_data(data, value.length());
    key->set_key_type(&type);

    return FALSE;
  }

};

} //namespace keyring


#endif //MYSQL_VAULT_PARSER_H
























