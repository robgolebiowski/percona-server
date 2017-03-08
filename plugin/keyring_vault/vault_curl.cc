//
// Created by rob on 03.03.17.
//

#include "vault_curl.h"

namespace keyring
{

static size_t write_response_memory(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  std::stringstream *read_data = (std::stringstream *)userp;

  read_data->write((char*)contents, realsize);
  if (!read_data->good())
    return 0; //TODO:is this correct or error should be signalised somehow different ?
  return realsize;
}

my_bool Vault_curl::init(std::string *vault_url, std::string *auth_token)
{
  curl = curl_easy_init();
  if (curl == NULL)
    return TRUE; //Add logger
  this->token_header = "X-Vault-Token:" + *auth_token;
  this->vault_url = *vault_url + "/v1/secret"; //TODO:Change me - secrete should be separate option
  return FALSE;
}

my_bool Vault_curl::reset_curl_session()
{
  curl_easy_reset(curl);
  read_data_ss.str("");
  read_data_ss.clear();
  if (list != NULL)
  {
    curl_slist_free_all(list);
    list = NULL;
  }

  if ((list = curl_slist_append(list, token_header.c_str())) == NULL ||
      (list = curl_slist_append(list, "Content-Type: application/json")) == NULL ||
      curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_memory) != CURLE_OK ||
      curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&read_data_ss) != CURLE_OK ||
      curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list) != CURLE_OK)
  {
    //TODO: Log error
    return TRUE;
  }
  return FALSE;
}

my_bool Vault_curl::list_keys(std::string *response)
{
  long http_code = 0;

  if (reset_curl_session() ||
      curl_easy_setopt(curl, CURLOPT_URL, (vault_url + "?list=true").c_str()) != CURLE_OK ||
      curl_easy_perform(curl) != CURLE_OK ||
      curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code) != CURLE_OK)
  {
    //TODO: Log error - should I add CURLOPT_ERRORBUFFER ?
    return TRUE;
  }

  if (http_code == 404)
    *response=""; //no keys found
  else
    *response = read_data_ss.str();

  return FALSE;
}

my_bool Vault_curl::write_key(IKey *key, std::string *response)
{
  std::string postdata="{\"type\":\"" + *key->get_key_type() + "\",\"";
  postdata += "value\":\"";
  postdata.append((const char*)key->get_key_data(), key->get_key_data_size());
  postdata += "\"}";

  if (reset_curl_session() ||
      curl_easy_setopt(curl, CURLOPT_URL, (vault_url + '/' + *key->get_key_signature()).c_str()) != CURLE_OK ||
      curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata.c_str()) != CURLE_OK ||
      curl_easy_perform(curl) != CURLE_OK)
  {
    //TODO: Log error
    return TRUE;
  }
  *response = read_data_ss.str();
  return FALSE;
}

my_bool Vault_curl::read_key(IKey *key, std::string *response)
{
  if (reset_curl_session() ||
      curl_easy_setopt(curl, CURLOPT_URL, (vault_url + '/' + *key->get_key_signature()).c_str()) != CURLE_OK ||
      curl_easy_perform(curl) != CURLE_OK)
  {
    //TODO: Log error
    return TRUE;
  }
  *response = read_data_ss.str();
  return FALSE;
}

my_bool Vault_curl::delete_key(IKey *key, std::string *response)
{
  if (reset_curl_session() ||
      curl_easy_setopt(curl, CURLOPT_URL, (vault_url + '/' + *key->get_key_signature()).c_str()) != CURLE_OK ||
      curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE") != CURLE_OK ||
      curl_easy_perform(curl) != CURLE_OK)
  {
    //TODO: Log error
    return TRUE;
  }
  *response = read_data_ss.str();
  return FALSE;
}

}























