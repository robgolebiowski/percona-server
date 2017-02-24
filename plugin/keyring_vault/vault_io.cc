#include <my_global.h>
#include "vault_io.h"
#include <curl/curl.h>

namespace keyring {

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t
WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
  size_t realsize = size * nmemb;
  struct MemoryStruct *mem = (struct MemoryStruct *)userp;

  mem->memory = (char*)realloc(mem->memory, mem->size + realsize + 1);
  if(mem->memory == NULL) {
    /* out of memory! */
    printf("not enough memory (realloc returned NULL)\n");
    return 0;
  }

  memcpy(&(mem->memory[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->memory[mem->size] = 0;

  return realsize;
}

my_bool Vault_io::init(std::string *keyring_storage_url)
{
  CURL *curl= curl_easy_init();
  CURLcode res= CURLE_OK;
  struct MemoryStruct chunk;

  chunk.memory = (char*)malloc(1);  /* will be grown as needed by the realloc above */
  chunk.size = 0;    /* no data at this point */

  struct curl_slist *list = NULL;
  if(curl)
  {
//    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8200/secret?list=true");
    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:8200/v1/secret/hello?list");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    list = curl_slist_append(list,
                             "X-Vault-Token:f8e6f730-5f52-92a3-cce6-3fd3ce55ab21"); //Czy nie powinno być spacji po : ?
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
    res= curl_easy_perform(curl);
  }

  if (res == CURLE_OK)
  {
    printf("%lu bytes retrieved\n", (long)chunk.size);
    printf("%s\n", chunk.memory);
  }

  return res != CURLE_OK;
}

} //namespace keyring

