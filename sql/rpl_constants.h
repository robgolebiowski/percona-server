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
//#include "my_aes.h" //TODO:Robert:Dodalem to tutaj, czy prawidlowo ?
#include "my_crypt.h"

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

//TODO:Robert: Temporary removed

static const size_t ENCRYPTION_MASTER_KEY_NAME_MAX_LEN = 100;
//void get_master_key(ulint master_key_id,
//void get_binlog_key(char* srv_uuid,
		    //uchar** binlog_key)
//{
//#ifndef UNIV_INNOCHECKSUM
	//char*	key_type = NULL;
	//size_t	key_len;
	//char	key_name[ENCRYPTION_MASTER_KEY_NAME_MAX_LEN];
	//int	ret;

	//memset(key_name, 0, ENCRYPTION_MASTER_KEY_NAME_MAX_LEN);
        //DBUG_ASSERT(srv_uuid != NULL);
////	if (srv_uuid != NULL) {
		//snprintf(key_name, ENCRYPTION_MASTER_KEY_NAME_MAX_LEN,
			    //"%s-%s-%s", "percona_binlog_",
			    //srv_uuid, ":1");
////	} else {
		//[> For compitable with 5.7.11, we need to get master key with
		//server id. */
////		memset(key_name, 0, ENCRYPTION_MASTER_KEY_NAME_MAX_LEN);
////		ut_snprintf(key_name, ENCRYPTION_MASTER_KEY_NAME_MAX_LEN,
////			    "%s-%lu-%lu", ENCRYPTION_MASTER_KEY_PRIFIX,
////			    server_id, master_key_id);
	////}

	//[> We call key ring API to get master key here. <]
	//ret = my_key_fetch(key_name, &key_type, NULL,
			   //reinterpret_cast<void**>(binlog_key), &key_len);

	//if (key_type) {
		//my_free(key_type);
	//}

	//if (ret) {
		//*binlog_key = NULL;
////		ib::error() << "Encryption can't find master key, please check"
////				" the keyring plugin is loaded.";
	//}

//#ifdef UNIV_ENCRYPT_DEBUG
//[>	if (!ret && *master_key) {
		//fprintf(stderr, "Fetched master key:%lu ", master_key_id);
		//ut_print_buf(stderr, *master_key, key_len);
		//fprintf(stderr, "\n");
	//}*/
//#endif [> DEBUG_TDE <]

//#endif
//}

static const size_t ENCRYPTION_SERVER_UUID_LEN = 36;
static const size_t ENCRYPTION_KEY_LEN = 32;

//void create_binlog_key(uchar** binlog_key)
//{
//#ifndef UNIV_INNOCHECKSUM
        //char*   key_type = NULL;
        //size_t  key_len;
        //char    key_name[ENCRYPTION_MASTER_KEY_NAME_MAX_LEN];
        //int     ret;

        //char	uuid[ENCRYPTION_SERVER_UUID_LEN + 1] = {0};

        //[> If uuid does not match with current server uuid,
        //set uuid as current server uuid. */
        ////if (strcmp(uuid, server_uuid) != 0) {
        //memcpy(uuid, server_uuid, ENCRYPTION_SERVER_UUID_LEN);
        ////}
        //memset(key_name, 0, ENCRYPTION_MASTER_KEY_NAME_MAX_LEN);

        //[> Generate new master key <]
        //snprintf(key_name, ENCRYPTION_MASTER_KEY_NAME_MAX_LEN,
                    //"%s-%s-%s", "percona_binlog_",
                    //uuid, ":1");

        //[> We call key ring API to generate master key here. <]
        //ret = my_key_generate(key_name, "AES",
                              //NULL, ENCRYPTION_KEY_LEN);

        //[> We call key ring API to get master key here. <]
        //ret = my_key_fetch(key_name, &key_type, NULL,
                           //reinterpret_cast<void**>(binlog_key),
                           //&key_len);

        //if (ret || *binlog_key == NULL) {
                ////ib::error() << "Encryption can't find master key, please check"
                ////                " the keyring plugin is loaded.";
                //*binlog_key = NULL;
        ////} else {  //Temporary disabling master key id
        ////        master_key_id++;
        //}

        //if (key_type) {
                //my_free(key_type);
        //}
//#endif
//}


#define BINLOG_CRYPTO_SCHEME_LENGTH 1
#define BINLOG_KEY_VERSION_LENGTH   4
#define BINLOG_IV_LENGTH            MY_AES_BLOCK_SIZE
#define BINLOG_IV_OFFS_LENGTH       4
#define BINLOG_NONCE_LENGTH         (BINLOG_IV_LENGTH - BINLOG_IV_OFFS_LENGTH)

struct Binlog_crypt_data {
  uint  scheme;
  uint  key_version, key_length, ctx_size;
  //uchar key[MY_AES_MAX_KEY_LENGTH];
  uchar *key;
  uchar nonce[BINLOG_NONCE_LENGTH];
  uint dst_len; //TODO:Robert:This is added by me.
  uchar iv[BINLOG_IV_LENGTH];

  //TODO:Robert: This is temporary added by me
  Binlog_crypt_data()
  {
    scheme = 0;
  }

  //Binlog_crypt_data(const Binlog_crypt_data &b)
  //{
    //this->scheme= b.scheme;
    //this->key_version = b.key_verion;
    //this->key= b.key;
    //memcpy(this->iv, b.iv, BINLOG_IV_LENGTH);
    //this->dst_len = b.dst_len;
    //memcpy(this->nonce, b.nonce, BINLOG_NONCE_LENGTH);
  //}

  int init(uint sch, uint kv)
  {
//TODO:Robert: Bede potrzebowal rozroznienia pomiedzy binlogiem i relay logiem ?
/*
    get_binlog_key(server_uuid, &key);
    if (key == NULL)
      create_binlog_key(&key);*/
    key=(uchar*)"1111111111111111";

    scheme= sch;
    ctx_size= my_aes_ctx_size(MY_AES_ECB);
    key_version= 1;//kv;
    key_length= 16;
    if (key==NULL)
      return 1;
    return 0;

    //return encryption_key_get(ENCRYPTION_KEY_SYSTEM_DATA, kv, key, &key_length);
  }

  void set_iv(uchar* iv, uint32 offs) const
  {
    memcpy(iv, nonce, BINLOG_NONCE_LENGTH);
    int4store(iv + BINLOG_NONCE_LENGTH, offs);

    //memcpy(this->iv, nonce, BINLOG_NONCE_LENGTH);
    //int4store(this->iv + BINLOG_NONCE_LENGTH, offs);
  }

  uchar* get_iv()
  {
    return iv;
  }
};


#endif /* RPL_CONSTANTS_H */
