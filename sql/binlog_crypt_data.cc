#include "binlog_crypt_data.h"

#include "my_global.h"
#include "my_sys.h"
#ifdef MYSQL_SERVER
#include <mysql/service_mysql_keyring.h>
#endif
#include <algorithm>
#include <boost/move/unique_ptr.hpp>

Binlog_crypt_data::Binlog_crypt_data()
  : key_length(0)
  , key(NULL)
  , enabled(false)
  , scheme(0)
{}

Binlog_crypt_data::~Binlog_crypt_data()
{
  free_key(key, key_length);
}

Binlog_crypt_data::Binlog_crypt_data(const Binlog_crypt_data &b)
{
  enabled = b.enabled;
  key_version = b.key_version;
  if (b.key_length && b.key != NULL)
  {
    key= reinterpret_cast<uchar*>(my_malloc(PSI_NOT_INSTRUMENTED, b.key_length, MYF(MY_WME)));
    memcpy(key, b.key, b.key_length);
  }
  else
    key= NULL;

  key_length= b.key_length;
  memcpy(iv, b.iv, BINLOG_IV_LENGTH);
  memcpy(nonce, b.nonce, BINLOG_NONCE_LENGTH);
}

void Binlog_crypt_data::free_key(uchar *&key, size_t &key_length)
{
  if (key != NULL)
  {
    DBUG_ASSERT(key_length == 16);
    memset_s(key, 512, 0, key_length);
    my_free(key);
    key= NULL;
    key_length= 0;
  }
}

Binlog_crypt_data& Binlog_crypt_data::operator=(Binlog_crypt_data b)
{
  enabled= b.enabled;
  key_version= b.key_version;
  key_length= b.key_length;
  std::swap(this->key, b.key);
  key_length= b.key_length;
  memcpy(iv, b.iv, BINLOG_IV_LENGTH);
  memcpy(nonce, b.nonce, BINLOG_NONCE_LENGTH);
  return *this;
}

bool Binlog_crypt_data::load_latest_binlog_key()
{
  free_key(key, key_length);
#ifdef MYSQL_SERVER
  boost::movelib::unique_ptr<char, void (*)(void*)> system_key_type(NULL, my_free);
  char *system_key_type_raw = NULL;
  size_t system_key_len = 0;
  uchar *system_key = NULL;

  DBUG_EXECUTE_IF("binlog_encryption_error_on_key_fetch",
                  { return true; } );

  int fetch_result = my_key_fetch("percona_binlog", &system_key_type_raw, NULL,
                                  reinterpret_cast<void**>(&system_key), &system_key_len);
  system_key_type.reset(system_key_type_raw);
  if (fetch_result)
  {
    free_key(system_key, system_key_len); // just in case
    return true;
  }
  system_key_type.reset();

  if (key == NULL)
  {
    my_key_generate("percona_binlog", "AES", NULL, 16);
    fetch_result = my_key_fetch("percona_binlog", &system_key_type_raw, NULL,
                                reinterpret_cast<void**>(&system_key), &system_key_len);
    system_key_type.reset(system_key_type_raw);
    if (fetch_result)
    {
      free_key(system_key, system_key_len); // just in case
      return true;
    }
    DBUG_ASSERT(strncmp(system_key_type.get(), "AES", 3) == 0);
  }

  if (parse_system_key(system_key, system_key_len, &key_version, &key, &key_length))
  {
    //something went terribly wrong - should I log some message here?
    return true;
  }
#endif
  return false;
}

bool Binlog_crypt_data::init_with_loaded_key(uint sch, const uchar* nonce)
{
  scheme= sch;
  //key_version= kv;
  //free_key(key, key_length);
  //key_length= 16; //TODO: Why is it here?

#ifdef MYSQL_SERVER
  DBUG_ASSERT(key != NULL && nonce != NULL);
  memcpy(this->nonce, nonce, BINLOG_NONCE_LENGTH);
#endif
  enabled= true;
  return false;
}

bool Binlog_crypt_data::init(uint sch, uint kv, const uchar* nonce)
{
  free_key(key, key_length);
#ifdef MYSQL_SERVER

#endif
  return false;
}

void Binlog_crypt_data::set_iv(uchar* iv, uint32 offs) const
{
  DBUG_ASSERT(key != NULL && key_length == 16);

  uchar iv_plain[BINLOG_IV_LENGTH];
  memcpy(iv_plain, nonce, BINLOG_NONCE_LENGTH);
  int4store(iv_plain + BINLOG_NONCE_LENGTH, offs);

  my_aes_encrypt(iv_plain, BINLOG_IV_LENGTH, iv,
                 key, key_length, my_aes_128_ecb, NULL, false);
}
