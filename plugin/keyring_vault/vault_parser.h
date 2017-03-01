//
// Created by rob on 24.02.17.
//

#ifndef MYSQL_VAULT_PARSER_H
#define MYSQL_VAULT_PARSER_H

#include "my_global.h"
#include "vault_key.h"
#include "vault_keys_list.h"

namespace keyring
{

//TODO: Add interface
class Vault_parser
{
public:

  my_bool parse_keys(std::string *payload, Vault_keys_list *keys)
  {
    /* payload is build as follows:
     * (...)"data":{"keys":["keysignature","keysignature"]}(...)
     * We need to retrieve keys signatures from it
     */
    std::size_t keys_pos = payload->find("keys");
    std::size_t closing_bracket = payload->find('}');
    if (keys_pos == std::string::npos || closing_bracket == std::string::npos) //no keys
      return TRUE; //change to something else? Probably add logger

    std::size_t keysignature_start = 0;
    std::size_t keysignature_end = keys_pos+5; //move after "keys"

    while ((keysignature_start = payload->find('\"', keysignature_end+1))
             != std::string::npos &&
           (keysignature_end = payload->find('\"', keysignature_start+1))
             != std::string::npos &&
           keysignature_start < closing_bracket)
    {
      std::string key_signature= payload->substr(keysignature_start+1,
                                                 keysignature_end-keysignature_start-1);
      std::string key_parameters[2];
      if (parse_key_signature(&key_signature, key_parameters))
      {
        for (std::list<IKey*>::iterator iter = keys->begin(); iter != keys->end();
             iter++)
          delete *iter;
        keys->clear();
        return TRUE;
      }
      IKey *vault_key= new Vault_key(key_parameters[0].c_str(), NULL,
                                     key_parameters[1].c_str(), NULL, 0);

      keys->push_back(vault_key);
    }
  }

  my_bool parse_key_signature(std::string *key_signature, std::string key_parameters[2])
  {
    //key_signature= lengthof(key_id)||key_id||lengthof(user_id)||user_id
    std::string digits("0123456789");
    size_t next_pos_to_start_from = 0;
    for (int i= 0; i < 2; ++i)
    {
      std::size_t key_id_pos = key_signature->find_first_not_of(digits, next_pos_to_start_from);
      std::string key_id_length = key_signature->substr(0, key_id_pos);
      int key_l = atoi(key_id_length.c_str());
      key_parameters[i] = key_signature->substr(key_id_pos, key_l);
      next_pos_to_start_from= key_id_pos+key_l;
    }
  }

};

} //namespace keyring


#endif //MYSQL_VAULT_PARSER_H
