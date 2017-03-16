//
// Created by rob on 03.03.17.
//

#include <algorithm>
#include "vault_curl.h"
#include "base64.h"

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

std::string Vault_curl::get_error_from_curl(CURLcode curl_code)
{
  size_t len = strlen(curl_errbuf);
  std::stringstream ss;
  if (curl_code != CURLE_OK)
  {
    ss << " Curl returned this error code: " << curl_code;
    ss << " with error message : ";
    if(len)
      ss << curl_errbuf;
    else
      ss << curl_easy_strerror(curl_code);
  }
  return ss.str();
}

my_bool Vault_curl::init(std::string *vault_url, std::string *auth_token)
{
  curl = curl_easy_init();
  if (curl == NULL)
  {
    logger->log(MY_ERROR_LEVEL, "Could not create CURL session");
    return TRUE; //Add logger
  }
  this->token_header = "X-Vault-Token:" + *auth_token;
  this->vault_url = *vault_url + "/v1/secret"; //TODO:Change me - secrete should be separate option
  return FALSE;
}

my_bool Vault_curl::reset_curl_session()
{
  CURLcode curl_res = CURLE_OK;
  curl_easy_reset(curl);
  read_data_ss.str("");
  read_data_ss.clear();
  curl_errbuf[0] = '\0';
  if (list != NULL)
  {
    curl_slist_free_all(list);
    list = NULL;
  }

  if ((list = curl_slist_append(list, token_header.c_str())) == NULL ||
      (list = curl_slist_append(list, "Content-Type: application/json")) == NULL ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf)) != CURLE_OK ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_memory)) != CURLE_OK ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&read_data_ss)) != CURLE_OK ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list)) != CURLE_OK)
  {
    logger->log(MY_ERROR_LEVEL, get_error_from_curl(curl_res).c_str());
    return TRUE;
  }
  return FALSE;
}

my_bool Vault_curl::list_keys(std::string *response)
{
  CURLcode curl_res = CURLE_OK;
  curl_easy_reset(curl);
  long http_code = 0;

  if (reset_curl_session() ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_URL, (vault_url + "?list=true").c_str())) != CURLE_OK ||
      (curl_res = curl_easy_perform(curl)) != CURLE_OK ||
      (curl_res = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &http_code)) != CURLE_OK)
  {
    logger->log(MY_ERROR_LEVEL,
                get_error_from_curl(curl_res).c_str());
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
  //base64 encoding
  uint64 memory_needed = base64_needed_encoded_length(key->get_key_data_size());
  char *base64_encoded_key_data = new char[memory_needed];
  if (base64_encode((const char*)key->get_key_data(), key->get_key_data_size(), base64_encoded_key_data) != 0)
  {
    delete[] base64_encoded_key_data;
    return TRUE; //TODO:Add logging
  }
  char* new_end = std::remove(base64_encoded_key_data, base64_encoded_key_data + memory_needed, '\n');
  memory_needed = new_end - base64_encoded_key_data;
  //base64 end of encoding
  

  CURLcode curl_res = CURLE_OK;
  std::string postdata="{\"type\":\"" + *key->get_key_type() + "\",\"";
  postdata += "value\":\"";
  postdata.append(base64_encoded_key_data, memory_needed-1); //base64 encode returns data with NULL terminating string - which we do not care about
  postdata += "\"}";
  delete[] base64_encoded_key_data; //no longer needed

  if (reset_curl_session() ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_URL,
                                   (vault_url + '/' + *key->get_key_signature()).c_str())) != CURLE_OK ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata.c_str())) != CURLE_OK ||
      (curl_res = curl_easy_perform(curl)) != CURLE_OK)
  {
    logger->log(MY_ERROR_LEVEL, get_error_from_curl(curl_res).c_str());
    return TRUE;
  }
  *response = read_data_ss.str();
  return FALSE;
}

my_bool Vault_curl::read_key(IKey *key, std::string *response)
{
  CURLcode curl_res = CURLE_OK;
  if (reset_curl_session() ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_URL, (vault_url + '/' + *key->get_key_signature()).c_str())) !=
      CURLE_OK ||
      (curl_res = curl_easy_perform(curl)) != CURLE_OK)
  {
    logger->log(MY_ERROR_LEVEL, get_error_from_curl(curl_res).c_str());
    return TRUE;
  }
  *response = read_data_ss.str();
  return FALSE;
}

my_bool Vault_curl::delete_key(IKey *key, std::string *response)
{
  CURLcode curl_res = CURLE_OK;
  if (reset_curl_session() ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_URL, (vault_url + '/' + *key->get_key_signature()).c_str())) !=
      CURLE_OK ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE")) != CURLE_OK ||
      (curl_res = curl_easy_perform(curl)) != CURLE_OK)
  {
    logger->log(MY_ERROR_LEVEL, get_error_from_curl(curl_res).c_str());
    return TRUE;
  }
  *response = read_data_ss.str();
  return FALSE;
}

}























