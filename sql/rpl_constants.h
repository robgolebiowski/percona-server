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

static const size_t ENCRYPTION_MASTER_KEY_NAME_MAX_LEN = 100;
static const size_t ENCRYPTION_SERVER_UUID_LEN = 36;
static const size_t ENCRYPTION_KEY_LEN = 32;

#define BINLOG_CRYPTO_SCHEME_LENGTH 1
#define BINLOG_KEY_VERSION_LENGTH   4
#define BINLOG_IV_LENGTH            MY_CRYPT_AES_BLOCK_SIZE
#define BINLOG_IV_OFFS_LENGTH       4
#define BINLOG_NONCE_LENGTH         (BINLOG_IV_LENGTH - BINLOG_IV_OFFS_LENGTH)

struct Binlog_crypt_data {
  uint  scheme;
  uint  key_version, key_length, ctx_size;
  uchar *key;
  uchar nonce[BINLOG_NONCE_LENGTH];
  uint dst_len;
  uchar iv[BINLOG_IV_LENGTH];

  Binlog_crypt_data()
  {
    scheme = 0;
  }

  Binlog_crypt_data& operator=(Binlog_crypt_data b)
  {
    if (b.scheme == 1)
    {
      this->scheme= b.scheme;
      this->key_version = b.key_version;
      this->ctx_size= b.ctx_size;
      this->key= new uchar[b.key_length];
      memcpy(this->key, b.key, b.key_length);
      this->key_length= b.key_length;
      memcpy(this->iv, b.iv, BINLOG_IV_LENGTH);
      this->dst_len = b.dst_len;
      memcpy(this->nonce, b.nonce, BINLOG_NONCE_LENGTH);
    }

    return *this;
  }

  int init(uint sch, uint kv)
  {
    scheme= sch;
    ctx_size= my_aes_ctx_size(MY_AES_ECB);
    key_version= kv;
    key_length= 16;

#ifdef MYSQL_SERVER
    char *key_type = NULL;
    size_t key_len;
    if (my_key_fetch("percona_binlog_system_key", &key_type, NULL,
                     reinterpret_cast<void**>(&key), &key_len) ||
        (key != NULL && key_len != 16))
      return 1;

    if (key == NULL)
    {
      my_key_generate("percona_binlog_system_key", "AES", NULL, 16);
      if (my_key_fetch("percona_binlog_system_key", &key_type, NULL,
                       reinterpret_cast<void**>(&key), &key_len) ||
          key_len != 16)
        return 1;
    }
#endif    
    return 0;
  }

  void set_iv(uchar* iv, uint32 offs) const
  {
    memcpy(iv, nonce, BINLOG_NONCE_LENGTH);
    int4store(iv + BINLOG_NONCE_LENGTH, offs);
  }

  uchar* get_iv()
  {
    return iv;
  }
};


#endif /* RPL_CONSTANTS_H */
