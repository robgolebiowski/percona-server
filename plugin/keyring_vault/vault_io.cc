#include <my_global.h>
#include "vault_io.h"
#include <curl/curl.h>
#include <sstream>

namespace keyring {

//struct MemoryStruct {
//    char *memory;
//    size_t size;
//};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
//  struct MemoryStruct *mem = (struct MemoryStruct *)userp;
  std::stringstream *read_data = (std::stringstream *)userp;

//  mem->memory = (char*)realloc(mem->memory, mem->size + realsize + 1);
//  if(mem->memory == NULL) {
//    /* out of memory! */
//    printf("not enough memory (realloc returned NULL)\n");
//    return 0;
//  }

//  memcpy(&(mem->memory[mem->size]), contents, realsize);
  read_data->write((char*)contents, realsize);
  if (!read_data->good())
  {
    return 0;
  }
  return realsize;
}

my_bool Vault_io::init(std::string *keyring_storage_url)
{
  CURL *curl= curl_easy_init();
  CURLcode res= CURLE_OK;

  std::stringstream read_data_ss;

  struct curl_slist *list = NULL;
  if(curl)
  {
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8200/v1/secret?list=true");
//    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8200/v1/secret/hello?list");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&read_data_ss);
    list = curl_slist_append(list,
                             "X-Vault-Token:5993b8c7-bf11-972e-a501-6a021e489255"); //Czy nie powinno być spacji po : ?
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    res= curl_easy_perform(curl);
  }

//  std::string read_data= read_data_ss.str();
  json_response = read_data_ss.str();

  if (res == CURLE_OK)
  {
    printf("%lu bytes retrieved\n", (long)json_response.size());
    printf("%s\n", json_response.c_str());
  }
  //TODO: init powinno tylko sprawdzić czy połączenie z vaultem jest możliwe używająć danych, czy też od razu ściągnąć
  //listę kluczy ?


  return res != CURLE_OK;
}

my_bool Vault_io::get_serialized_object(ISerialized_object **serialized_object)
{
  *serialized_object= NULL;

  Vault_keys_list *keys = new Vault_keys_list();

  if (vault_parser.parse_keys(&json_response, keys))
  {
    delete keys;
    return TRUE;
  }

  if (keys->size() == 0)
  {
    delete keys;
    *serialized_object = NULL;
    return FALSE; //no keys
  }

  *serialized_object = keys;
  return FALSE;
}

my_bool Vault_io::retrieve_key_type_and_value(Vault_key *key)
{
  CURL *curl= curl_easy_init();
  CURLcode res= CURLE_OK;

  std::stringstream read_data_ss;

  struct curl_slist *list = NULL;
  if(curl)
  {
    std::string request = "http://127.0.0.1:8200/v1/secret/";
    request += *key->get_key_signature();

    curl_easy_setopt(curl, CURLOPT_URL, request.c_str());
//    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8200/v1/secret/hello?list");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&read_data_ss);
    list = curl_slist_append(list,
                             "X-Vault-Token:5993b8c7-bf11-972e-a501-6a021e489255"); //Czy nie powinno być spacji po : ?
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    res= curl_easy_perform(curl);
  }

//  std::string read_data= read_data_ss.str();
  json_response = read_data_ss.str();

  return vault_parser.parse_key_data(&json_response, key);
}

ISerializer* Vault_io::get_serializer()
{
  return &vault_key_serializer;
}

my_bool Vault_io::flush_to_storage(ISerialized_object *serialized_object)
{
  Vault_key *vault_key = dynamic_cast<Vault_key*>(serialized_object);

  if (vault_key == NULL)
    return TRUE;

  CURL *curl= curl_easy_init();
  CURLcode res= CURLE_OK;

  std::stringstream read_data_ss;

  struct curl_slist *list = NULL;
  if(curl)
  {
    std::string request = "http://127.0.0.1:8200/v1/secret/";
    request += *vault_key->get_key_signature();

    curl_easy_setopt(curl, CURLOPT_URL, request.c_str());
//    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8200/v1/secret/hello?list");
    std::string postdata="{\"type\":\"" + *vault_key->get_key_type() + "\",\"";
    postdata += "value\":\"" + std::string((const char*)vault_key->get_key_data(), vault_key->get_key_data_size());
    postdata += "\"}";
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postdata.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&read_data_ss);
    list = curl_slist_append(list,
                             "X-Vault-Token:5993b8c7-bf11-972e-a501-6a021e489255"); //Czy nie powinno być spacji po : ?
    list = curl_slist_append(list,
                             "Content-Type: application/json"); //Czy nie powinno być spacji po : ?
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    res= curl_easy_perform(curl);
  }

//  std::string read_data= read_data_ss.str();
  json_response = read_data_ss.str();
  return FALSE;
//  return vault_parser.parse_key_data(&json_response, key);
}

} //namespace keyring






























