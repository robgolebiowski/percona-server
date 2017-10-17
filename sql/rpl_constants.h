/* Copyright (c) 2007 MySQL AB, 2008 Sun Microsystems, Inc.
   Use is subject to license terms.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifndef RPL_CONSTANTS_H
#define RPL_CONSTANTS_H

#include "my_global.h"
#include "my_crypt.h"
#include "my_sys.h"
#ifdef MYSQL_SERVER
#include <mysql/service_mysql_keyring.h>
#endif

/*
  Constants used to parse the stream of bytes sent by a slave
  when commands COM_BINLOG_DUMP or COM_BINLOG_DUMP_GTID are
  sent.
*/
const int BINLOG_POS_INFO_SIZE= 8;
const int BINLOG_DATA_SIZE_INFO_SIZE= 4;
const int BINLOG_POS_OLD_INFO_SIZE= 4;
const int BINLOG_FLAGS_INFO_SIZE= 2;
const int BINLOG_SERVER_ID_INFO_SIZE= 4;
const int BINLOG_NAME_SIZE_INFO_SIZE= 4;

const int BINLOG_DUMP_NON_BLOCK= 1<<0;

/**
   Enumeration of the reserved formats of Binlog extra row information
*/
enum ExtraRowInfoFormat {
  /** Ndb format */
  ERIF_NDB          =   0,

  /** Reserved formats  0 -> 63 inclusive */
  ERIF_LASTRESERVED =  63,

  /**
      Available / uncontrolled formats
      64 -> 254 inclusive
  */
  ERIF_OPEN1        =  64,
  ERIF_OPEN2        =  65,

  ERIF_LASTOPEN     =  254,

  /**
     Multi-payload format 255

      Length is total length, payload is sequence of
      sub-payloads with their own headers containing
      length + format.
  */
  ERIF_MULTI        =  255
};

//static const size_t ENCRYPTION_MASTER_KEY_NAME_MAX_LEN = 100;
//static const size_t ENCRYPTION_SERVER_UUID_LEN = 36;
//static const size_t ENCRYPTION_KEY_LEN = 32;

//#define BINLOG_CRYPTO_SCHEME_LENGTH 1
//#define BINLOG_KEY_VERSION_LENGTH   4
//#define BINLOG_IV_LENGTH            MY_AES_BLOCK_SIZE
//#define BINLOG_IV_OFFS_LENGTH       4
//#define BINLOG_NONCE_LENGTH         (BINLOG_IV_LENGTH - BINLOG_IV_OFFS_LENGTH)

//enum Binlog_crypt_consts
//{
  //BINLOG_CRYPTO_SCHEME_LENGTH= 1,
  //BINLOG_KEY_VERSION_LENGTH= 4,
  //BINLOG_IV_LENGTH= MY_AES_BLOCK_SIZE,
  //BINLOG_IV_OFFS_LENGTH= 4,
  //BINLOG_NONCE_LENGTH= BINLOG_IV_LENGTH - BINLOG_IV_OFFS_LENGTH
//};

class Binlog_crypt_data {
  //uint  key_version, key_length;
  //uchar *key;
  //uchar nonce[BINLOG_NONCE_LENGTH];
  //uint dst_len;
  //uchar iv[BINLOG_IV_LENGTH];
public:
 
  //static const size_t binlog_crypto_scheme_length;
  //static const size_t binlog_key_version_length;
  //static const size_t binlog_iv_length;
  //static const size_t binlog_iv_offs_length;
  //static const size_t binlog_nonce_length;

  enum Binlog_crypt_consts
  {
    BINLOG_CRYPTO_SCHEME_LENGTH= 1,
    BINLOG_KEY_VERSION_LENGTH= 4,
    BINLOG_IV_LENGTH= MY_AES_BLOCK_SIZE,
    BINLOG_IV_OFFS_LENGTH= 4,
    BINLOG_NONCE_LENGTH= BINLOG_IV_LENGTH - BINLOG_IV_OFFS_LENGTH
  };



  Binlog_crypt_data()
    : key(NULL)
    , enabled(false)  
    , scheme(0)
  {}

  void free_key()
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

  ~Binlog_crypt_data()
  {
    free_key();
  }

  Binlog_crypt_data(const Binlog_crypt_data &b)
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
    dst_len = b.dst_len;
    memcpy(nonce, b.nonce, BINLOG_NONCE_LENGTH);
  }

  Binlog_crypt_data& operator=(Binlog_crypt_data b)
  {
    enabled= b.enabled;
    key_version= b.key_version;
    key_length= b.key_length;
    std::swap(this->key, b.key);
    key_length= b.key_length;
    memcpy(iv, b.iv, BINLOG_IV_LENGTH);
    dst_len= b.dst_len;
    memcpy(nonce, b.nonce, BINLOG_NONCE_LENGTH);

    return *this;
  }

  //Binlog_crypt_data& operator=(const Binlog_crypt_data &b)
  //{
    //if (b.is_enabled())
    //{
      //this->scheme= b.scheme;
      //this->key_version = b.key_version;
      //free_key();
      //if (b.key_length && b.key != NULL)
      //{
        //this->key= reinterpret_cast<uchar*>(my_malloc(PSI_NOT_INSTRUMENTED, b.key_length, MYF(MY_WME)));
        //memcpy(this->key, b.key, b.key_length);
      //}
      //this->key_length= b.key_length;
      //memcpy(this->iv, b.iv, BINLOG_IV_LENGTH);
      //this->dst_len = b.dst_len;
      //memcpy(this->nonce, b.nonce, BINLOG_NONCE_LENGTH);
    //}
    //return *this;
  //}

  bool init(uint sch, uint kv, const uchar* nonce)
  {
    scheme= sch;
    //ctx_size= my_aes_ctx_size(MY_AES_ECB);
    key_version= kv;
    free_key();
    key_length= 16;

#ifdef MYSQL_SERVER
    DBUG_ASSERT(nonce != NULL);
    memcpy(this->nonce, nonce, BINLOG_NONCE_LENGTH);

    char *key_type= NULL;
    size_t key_len;

    DBUG_EXECUTE_IF("binlog_encryption_error_on_key_fetch",
                    { return 1; } );

    if (my_key_fetch("percona_binlog", &key_type, NULL,
                     reinterpret_cast<void**>(&key), &key_len) ||
        (key != NULL && key_len != 16))
    {
      free_key();
      if (key_type != NULL)
        my_free(key_type);
      return true;
    }
    my_free(key_type);
    key_type= NULL;

    if (key == NULL)
    {
      my_key_generate("percona_binlog", "AES", NULL, 16);
      if (my_key_fetch("percona_binlog", &key_type, NULL,
                       reinterpret_cast<void**>(&key), &key_len) ||
          key_len != 16)
      {
        free_key();
        if (key_type != NULL)
          my_free(key_type);
        return true;
      }
      DBUG_ASSERT(strncmp(key_type, "AES", 3) == 0);
    }
    my_free(key_type);
#endif
    enabled= true;
    return false;
  }

  bool is_enabled() const
  {
    return enabled;
  }

  void disable()
  {
    enabled= false; 
  }

  //void set_nonce(uchar *nonce)
  //{
    //DBUG_ASSERT(nonce != NULL);
    //memcpy(this->nonce, nonce, BINLOG_NONCE_LENGTH);
  //}

  uchar *get_key() const
  {
    return key;
  }

  size_t get_keys_length() const
  {
    return key_length;
  }

  void set_iv(uchar* iv, uint32 offs) const
  {
    DBUG_ASSERT(key != NULL && key_length == 16);

    uchar iv_plain[BINLOG_IV_LENGTH];
    memcpy(iv_plain, nonce, BINLOG_NONCE_LENGTH);
    int4store(iv_plain + BINLOG_NONCE_LENGTH, offs);

    my_aes_encrypt(iv_plain, BINLOG_IV_LENGTH, iv,
                   key, key_length, my_aes_128_ecb, NULL, false);
  }

private:
  uint  key_version;
  size_t key_length;//, ctx_size;
  uchar *key;
  uchar nonce[BINLOG_NONCE_LENGTH];
  uint dst_len;
  uchar iv[BINLOG_IV_LENGTH];

  bool enabled;
  uint scheme;
};


//#define BINLOG_CRYPTO_SCHEME_LENGTH 1
//#define BINLOG_KEY_VERSION_LENGTH   4
//#define BINLOG_IV_LENGTH            MY_AES_BLOCK_SIZE
//#define BINLOG_IV_OFFS_LENGTH       4
//#define BINLOG_NONCE_LENGTH         (BINLOG_IV_LENGTH - BINLOG_IV_OFFS_LENGTH)

//const size_t Binlog_crypt_data::binlog_crypto_scheme_length= 1;
//const size_t Binlog_crypt_data::binlog_key_version_length= 4;
//const size_t Binlog_crypt_data::binlog_iv_length= MY_AES_BLOCK_SIZE;
//const size_t Binlog_crypt_data::binlog_iv_offs_length= 4;
//const size_t Binlog_crypt_data::binlog_nonce_length= Binlog_crypt_data::binlog_iv_length - Binlog_crypt_data::binlog_iv_offs_length;

#endif /* RPL_CONSTANTS_H */
