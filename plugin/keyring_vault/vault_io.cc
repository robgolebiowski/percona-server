#include <my_global.h>
#include "vault_io.h"
#include "buffer.h"
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
//  struct MemoryStruct chunk;

//  chunk.memory = (char*)malloc(1);  /* will be grown as needed by the realloc above */
//  chunk.size = 0;    /* no data at this point */

  std::stringstream read_data_ss;

  struct curl_slist *list = NULL;
  if(curl)
  {
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8200/v1/secret?list=true");
//    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8200/v1/secret/hello?list");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&read_data_ss);
    list = curl_slist_append(list,
                             "X-Vault-Token:b243f84b-ce4e-f912-6739-88bd7f61fa8b"); //Czy nie powinno być spacji po : ?
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    res= curl_easy_perform(curl);
  }

//  std::string read_data= read_data_ss.str();
  json_response = read_data_ss.str();

  if (res == CURLE_OK)
  {
    printf("%lu bytes retrieved\n", (long)read_data.size());
    printf("%s\n", read_data.c_str());
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

} //namespace keyring

