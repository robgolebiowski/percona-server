/*****************************************************************************
Copyright (C) 2013, 2015, Google Inc. All Rights Reserved.
Copyright (c) 2015, 2017, MariaDB Corporation.

This program is free software; you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation; version 2 of the License.

This program is distributed in the hope that it will be useful, but WITHOUT
ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Suite 500, Boston, MA 02110-1335 USA

*****************************************************************************/

/**************************************************//**
@file include/fil0crypt.h
The low-level file system encryption support functions

Created 04/01/2015 Jan Lindström
*******************************************************/

#ifndef fil0crypt_h
#define fil0crypt_h

#ifndef UNIV_INNOCHECKSUM

#include "os0event.h"
#include "my_crypt.h"
#include "log0types.h"
// TODO: Robert: This is temporary for fil_encryption_t
#include "fil0fil.h"


#endif /*! UNIV_INNOCHECKSUM */

#include "log0types.h"
/**
* Magic pattern in start of crypt data on page 0
*/
#define MAGIC_SZ 6

static const unsigned char CRYPT_MAGIC[MAGIC_SZ] = {
	's', 0xE, 0xC, 'R', 'E', 't' };

//static const char ENCRYPTION_PERCONA_SYSTEM_KEY_PREFIX[] = "percona_innodb";

/* This key will be used if nothing else is given */
#define FIL_DEFAULT_ENCRYPTION_KEY 0
#define ENCRYPTION_KEY_VERSION_INVALID        (~(unsigned int)0)
#define ENCRYPTION_KEY_VERSION_NOT_ENCRYPTED  (~(unsigned int)0) - 1

enum ENCRYPTION_ROTATION
{
   NONE,
   MASTER_KEY_TO_ROTATED_KEY,
   ROTATED_KEY_TO_MASTER_KEY
};

extern os_event_t fil_crypt_threads_event;

/**
 * CRYPT_SCHEME_UNENCRYPTED
 *
 * Used as intermediate state when convering a space from unencrypted
 * to encrypted
 */
/**
 * CRYPT_SCHEME_1
 *
 * xxx is AES_CTR or AES_CBC (or another block cypher with the same key and iv lengths)
 *  L = AES_ECB(KEY, IV)
 *  CRYPT(PAGE) = xxx(KEY=L, IV=C, PAGE)
 */

#define CRYPT_SCHEME_1 1
#define CRYPT_SCHEME_1_IV_LEN 16
#define CRYPT_SCHEME_UNENCRYPTED 0


//TODO:Robert:Those are mine
#define MY_AES_MAX_KEY_LENGTH 16
#define ENCRYPTION_SCHEME_BLOCK_LENGTH 16


/* Cached L or key for given key_version */
struct key_struct
{
	uint key_version;			/*!< Version of the key */
	uint key_length;			/*!< Key length */
	unsigned char key[MY_AES_MAX_KEY_LENGTH]; /*!< Cached key
                                                (that is L in CRYPT_SCHEME_1) */
};

//enum fil_encryption_t {
	//[>* Encrypted if innodb_encrypt_tables=ON (srv_encrypt_tables) <]
	//FIL_ENCRYPTION_DEFAULT,
	//[>* Encrypted <]
	//FIL_ENCRYPTION_ON,
	//[>* Not encrypted <]
	//FIL_ENCRYPTION_OFF
//};

struct st_encryption_scheme_key {
  unsigned int version;
  unsigned char key[ENCRYPTION_SCHEME_BLOCK_LENGTH];
};

struct st_encryption_scheme {
  unsigned char iv[ENCRYPTION_SCHEME_BLOCK_LENGTH];
  struct st_encryption_scheme_key key[3]; //TODO : Why do I need this ?
  unsigned int keyserver_requests;
  //unsigned char key[ENCRYPTION_SCHEME_BLOCK_LENGTH];
  unsigned int key_id;
  unsigned int type; 

  //void (*locker)(struct st_encryption_scheme *self, int release);
};

/** is encryption enabled */
extern ulong	srv_encrypt_tables;

/** Mutex helper for crypt_data->scheme
@param[in, out]	schme	encryption scheme
@param[in]	exit	should we exit or enter mutex ? */
void
crypt_data_scheme_locker(
	st_encryption_scheme*	scheme,
	int			exit);

struct fil_space_rotate_state_t
{
	time_t start_time;	/*!< time when rotation started */
	ulint active_threads;	/*!< active threads in space */
	ulint next_offset;	/*!< next "free" offset */
	ulint max_offset;	/*!< max offset needing to be rotated */
	uint  min_key_version_found; /*!< min key version found but not
				     rotated */
	lsn_t end_lsn;		/*!< max lsn created when rotating this
				space */
	bool starting;		/*!< initial write of IV */
	bool flushing;		/*!< space is being flushed at end of rotate */
	struct {
		bool is_active; /*!< is scrubbing active in this space */
		time_t last_scrub_completed; /*!< when was last scrub
					     completed */
	} scrubbing;
};

#ifndef UNIV_INNOCHECKSUM

bool encryption_key_id_exists(const char *key_id);

struct fil_space_crypt_t : st_encryption_scheme
{
 public:
	/** Constructor. Does not initialize the members!
	The object is expected to be placed in a buffer that
	has been zero-initialized. */
	fil_space_crypt_t(
		uint new_type,
		uint new_min_key_version,
		uint new_key_id,
		fil_encryption_t new_encryption,
                bool create_key, // is used when we have a new tablespace to encrypt and is not used when we read a crypto from page0
                ENCRYPTION_ROTATION encryption_rotation = NONE)
		: st_encryption_scheme(),
		min_key_version(new_min_key_version),
		page0_offset(0),
		encryption(new_encryption),
		key_found(0),
		rotate_state(),
                encryption_rotation(encryption_rotation)
	{
		key_id = new_key_id;
		if (my_random_bytes(iv, sizeof(iv)) != MY_AES_OK)  // TODO:Robert: This can return error and because of that it should not be in constructor
                  type = 0; //TODO:Robert: This is temporary to get rid of unused variable problem
                mutex_create(LATCH_ID_FIL_CRYPT_DATA_MUTEX, &mutex);
		//locker = crypt_data_scheme_locker; // TODO:Robert: Co to za locker, nie mogę znaleść jego definicji nawet w mariadb
		type = new_type;

		if (new_encryption == FIL_ENCRYPTION_OFF ||
			(!srv_encrypt_tables &&
			 new_encryption == FIL_ENCRYPTION_DEFAULT)) {
			type = CRYPT_SCHEME_UNENCRYPTED;
                        min_key_version = ENCRYPTION_KEY_VERSION_NOT_ENCRYPTED;
                        //ut_ad(0);
		} else {
			type = CRYPT_SCHEME_1;
                        if (create_key)
                        {
         			min_key_version= key_get_latest_version(); //This means table was created with ROTATED_KEYS = thus we know that this table is encrypted
                                                                          //min_key_version should be set to key_version, when create_key is false it means it was not created
                                                                          //with ROTATED_KEYS
                                //min_key_version = ENCRYPTION_KEY_VERSION_NOT_ENCRYPTED;
                        }
                        else
                                min_key_version = ENCRYPTION_KEY_VERSION_NOT_ENCRYPTED; //it will be filled in later by a caller - which read crypto - if it going to be read from page0
                                //min_key_version = key_get_latest_version();
                        //min_key_version = ENCRYPTION_KEY_VERSION_NOT_ENCRYPTED;
                        //ut_ad(min_key_version == 0);
		}

		key_found = min_key_version; // TODO:This does not make much sense now - always true
	}

	/** Destructor */
	~fil_space_crypt_t()
	{
                mutex_free(&mutex);
	}

	/** Get latest key version from encryption plugin
	@retval key_version or
	@retval ENCRYPTION_KEY_VERSION_INVALID if used key_id
	is not found from encryption plugin. */
	uint key_get_latest_version(void);

	/** Returns true if key was found from encryption plugin
	and false if not. */
	bool is_key_found() const {
		return true; //TODO:temporary key is always found //key_found != ENCRYPTION_KEY_VERSION_INVALID;
	}

	/** Returns true if tablespace should be encrypted */
	bool should_encrypt() const {
		return ((encryption == FIL_ENCRYPTION_ON) ||
			(srv_encrypt_tables &&
				encryption == FIL_ENCRYPTION_DEFAULT));
	}

	/** Return true if tablespace is encrypted. */
	bool is_encrypted() const {
		return (encryption != FIL_ENCRYPTION_OFF);
	}

	/** Return true if default tablespace encryption is used, */
	bool is_default_encryption() const {
		return (encryption == FIL_ENCRYPTION_DEFAULT);
	}

	/** Return true if tablespace is not encrypted. */
	bool not_encrypted() const {
		return (encryption == FIL_ENCRYPTION_OFF);
	}

	/** Write crypt data to a page (0)
	@param[in]	space	tablespace
	@param[in,out]	page0	first page of the tablespace
	@param[in,out]	mtr	mini-transaction */
	void write_page0(const fil_space_t* space, byte* page0, mtr_t* mtr);

	uint min_key_version; // min key version for this space
	ulint page0_offset;   // byte offset on page 0 for crypt data
	fil_encryption_t encryption; // Encryption setup

	ib_mutex_t mutex;   // mutex protecting following variables

	/** Return code from encryption_key_get_latest_version.
        If ENCRYPTION_KEY_VERSION_INVALID encryption plugin
	could not find the key and there is no need to call
	get_latest_key_version again as keys are read only
	at startup. */
	uint key_found;

	fil_space_rotate_state_t rotate_state;

        ENCRYPTION_ROTATION encryption_rotation;
};



//struct fil_space_crypt_t : st_encryption_scheme
//{
 //public:
	//[>* Constructor. Does not initialize the members!
	//The object is expected to be placed in a buffer that
	//has been zero-initialized. */

			////fil_space_crypt_t(
				//////type,
				////min_key_version,
				////key);
				//////encrypt_mode);


	//fil_space_crypt_t(
		//uint new_min_key_version,
		//const uchar *key,
                //fil_encryption_t new_encryption)
		//: st_encryption_scheme(),
		//min_key_version(new_min_key_version),
		//page0_offset(0),
		//encryption(new_encryption),
		//key_found(0),
		//rotate_state()
	//{
		////key_id = new_key_id;
		//my_random_bytes(iv, sizeof(iv));
		//mutex_create(LATCH_ID_FIL_CRYPT_DATA_MUTEX, &mutex);
		//locker = crypt_data_scheme_locker;
		////type = new_type;
                //mempy(this->key, key, ENCRYPTION_SCHEME_BLOCK_LENGTH);

		//if (new_encryption == FIL_ENCRYPTION_OFF ||
			//(!srv_encrypt_tables &&
			 //new_encryption == FIL_ENCRYPTION_DEFAULT)) {
			//type = CRYPT_SCHEME_UNENCRYPTED;
		//} else {
			//type = CRYPT_SCHEME_1;
			//min_key_version = key_get_latest_version();
		//}

		//key_found = min_key_version;
	//}

	//[>* Destructor <]
	//~fil_space_crypt_t()
	//{
		//mutex_free(&mutex);
	//}

	//[>* Get latest key version from encryption plugin
	//@retval key_version or
	//@retval ENCRYPTION_KEY_VERSION_INVALID if used key_id
	//is not found from encryption plugin. */
	//uint key_get_latest_version(void);

	//[>* Returns true if key was found from encryption plugin
	//and false if not. */
	//bool is_key_found() const {
		//return key_found != ENCRYPTION_KEY_VERSION_INVALID;
	//}

	//[>* Returns true if tablespace should be encrypted <]
	//bool should_encrypt() const {
		//return ((encryption == FIL_ENCRYPTION_ON) ||
			//(srv_encrypt_tables &&
				//encryption == FIL_ENCRYPTION_DEFAULT));
	//}

	//[>* Return true if tablespace is encrypted. <]
	//bool is_encrypted() const {
		//return (encryption != FIL_ENCRYPTION_OFF);
	//}

	//[>* Return true if default tablespace encryption is used, <]
	//bool is_default_encryption() const {
		//return (encryption == FIL_ENCRYPTION_DEFAULT);
	//}

	//[>* Return true if tablespace is not encrypted. <]
	//bool not_encrypted() const {
		//return (encryption == FIL_ENCRYPTION_OFF);
	//}

	//[>* Write crypt data to a page (0)
	//@param[in]	space	tablespace
	//@param[in,out]	page0	first page of the tablespace
	//@param[in,out]	mtr	mini-transaction */
	//void write_page0(const fil_space_t* space, byte* page0, mtr_t* mtr);

	//uint min_key_version; // min key version for this space
	//ulint page0_offset;   // byte offset on page 0 for crypt data
        //fil_encryption_t encryption; // Encryption setup

	//ib_mutex_t mutex;   // mutex protecting following variables

	//[>* Return code from encryption_key_get_latest_version.
        //If ENCRYPTION_KEY_VERSION_INVALID encryption plugin
	//could not find the key and there is no need to call
	//get_latest_key_version again as keys are read only
	//at startup. */
	//uint key_found;

	//fil_space_rotate_state_t rotate_state;
//};

/** Status info about encryption */
struct fil_space_crypt_status_t {
	ulint space;             /*!< tablespace id */
	ulint scheme;            /*!< encryption scheme */
	uint  min_key_version;   /*!< min key version */
	uint  current_key_version;/*!< current key version */
	uint  keyserver_requests;/*!< no of key requests to key server */
	uint key_id;            /*!< current key_id */
	bool rotating;           /*!< is key rotation ongoing */
	bool flushing;           /*!< is flush at end of rotation ongoing */
	ulint rotate_next_page_number; /*!< next page if key rotating */
	ulint rotate_max_page_number;  /*!< max page if key rotating */
};

/** Statistics about encryption key rotation */
struct fil_crypt_stat_t {
	ulint pages_read_from_cache;
	ulint pages_read_from_disk;
	ulint pages_modified;
	ulint pages_flushed;
	ulint estimated_iops;
};

/** Status info about scrubbing */
struct fil_space_scrub_status_t {
	ulint space;             /*!< tablespace id */
	bool compressed;        /*!< is space compressed  */
	time_t last_scrub_completed;  /*!< when was last scrub completed */
	bool scrubbing;               /*!< is scrubbing ongoing */
	time_t current_scrub_started; /*!< when started current scrubbing */
	ulint current_scrub_active_threads; /*!< current scrub active threads */
	ulint current_scrub_page_number; /*!< current scrub page no */
	ulint current_scrub_max_page_number; /*!< current scrub max page no */
};

/*********************************************************************
Init space crypt */
void
fil_space_crypt_init();

/*********************************************************************
Cleanup space crypt */
void
fil_space_crypt_cleanup();

/**
Create a fil_space_crypt_t object
@param[in]	encrypt_mode	FIL_ENCRYPTION_DEFAULT or
				FIL_ENCRYPTION_ON or
				FIL_ENCRYPTION_OFF

@param[in]	key_id		Encryption key id
@return crypt object */
fil_space_crypt_t*
fil_space_create_crypt_data(
	fil_encryption_t	encrypt_mode,
	uint			key_id,
        bool                    create_key = true)
	MY_ATTRIBUTE((warn_unused_result));

/******************************************************************
Merge fil_space_crypt_t object
@param[in,out]	dst		Destination cryp data
@param[in]	src		Source crypt data */
void
fil_space_merge_crypt_data(
	fil_space_crypt_t* dst,
	const fil_space_crypt_t* src);

/** Initialize encryption parameters from a tablespace header page.
@param[in]	page_size	page size of the tablespace
@param[in]	page		first page of the tablespace
@return crypt data from page 0
@retval	NULL	if not present or not valid */
//UNIV_INTERN
//fil_space_crypt_t*
//fil_space_read_crypt_data(const page_size_t& page_size, const byte* page)
	//MY_ATTRIBUTE((nonnull, warn_unused_result));

fil_space_crypt_t*
fil_space_read_crypt_data(const page_size_t& page_size, const byte* page);
  
//bool fil_space_read_crypt_data(const page_size_t& page_size, const byte* page, ulint space_id);

/**
Free a crypt data object
@param[in,out] crypt_data	crypt data to be freed */
void
fil_space_destroy_crypt_data(
	fil_space_crypt_t **crypt_data);

/******************************************************************
Parse a MLOG_FILE_WRITE_CRYPT_DATA log entry
@param[in]	ptr		Log entry start
@param[in]	end_ptr		Log entry end
@param[in]	block		buffer block
@param[out]	err		DB_SUCCESS or DB_DECRYPTION_FAILED
@return position on log buffer */
byte*
fil_parse_write_crypt_data(
	byte*			ptr,
	const byte*		end_ptr,
	const buf_block_t*	block,
	ulint 		        len)
	MY_ATTRIBUTE((warn_unused_result));

/** Encrypt a buffer.
@param[in,out]		crypt_data	Crypt data
@param[in]		space		space_id
@param[in]		offset		Page offset
@param[in]		lsn		Log sequence number
@param[in]		src_frame	Page to encrypt
@param[in]		page_size	Page size
@param[in,out]		dst_frame	Output buffer
@return encrypted buffer or NULL */
byte*
fil_encrypt_buf(
	fil_space_crypt_t*	crypt_data,
	ulint			space,
	ulint			offset,
	lsn_t			lsn,
	const byte*		src_frame,
	const page_size_t&	page_size,
	byte*			dst_frame)
	MY_ATTRIBUTE((warn_unused_result));

/**
Encrypt a page.

@param[in]		space		Tablespace
@param[in]		offset		Page offset
@param[in]		lsn		Log sequence number
@param[in]		src_frame	Page to encrypt
@param[in,out]		dst_frame	Output buffer
@return encrypted buffer or NULL */
byte*
fil_space_encrypt(
	const fil_space_t* space,
	ulint		offset,
	lsn_t		lsn,
	byte*		src_frame,
	byte*		dst_frame)
	MY_ATTRIBUTE((warn_unused_result));

/**
Decrypt a page.
@param[in,out]	crypt_data		crypt_data
@param[in]	tmp_frame		Temporary buffer
@param[in]	page_size		Page size
@param[in,out]	src_frame		Page to decrypt
@param[out]	err			DB_SUCCESS or error
@return true if page decrypted, false if not.*/
bool
fil_space_decrypt(
	fil_space_crypt_t*	crypt_data,
	byte*			tmp_frame,
	const page_size_t&	page_size,
	byte*			src_frame,
	dberr_t*		err);

/******************************************************************
Decrypt a page
@param[in]	space			Tablespace
@param[in]	tmp_frame		Temporary buffer used for decrypting
@param[in,out]	src_frame		Page to decrypt
@param[out]	decrypted		true if page was decrypted
@return decrypted page, or original not encrypted page if decryption is
not needed.*/
byte*
fil_space_decrypt(
	const fil_space_t* space,
	byte*		tmp_frame,
	byte*		src_frame,
	bool*		decrypted)
	MY_ATTRIBUTE((warn_unused_result));

/******************************************************************
Calculate post encryption checksum
@param[in]	page_size	page size
@param[in]	dst_frame	Block where checksum is calculated
@return page checksum or BUF_NO_CHECKSUM_MAGIC
not needed. */
uint32_t
fil_crypt_calculate_checksum(
	const page_size_t&	page_size,
	const byte*		dst_frame)
	MY_ATTRIBUTE((warn_unused_result));

/*********************************************************************
Adjust thread count for key rotation
@param[in]	enw_cnt		Number of threads to be used */
void
fil_crypt_set_thread_cnt(
	uint	new_cnt);

/*********************************************************************
Adjust max key age
@param[in]	val		New max key age */
void
fil_crypt_set_rotate_key_age(
	uint	val);

/*********************************************************************
Adjust rotation iops
@param[in]	val		New max roation iops */
void
fil_crypt_set_rotation_iops(
	uint val);

/*********************************************************************
Adjust encrypt tables
@param[in]	val		New setting for innodb-encrypt-tables */
void
fil_crypt_set_encrypt_tables(
	uint val);

/*********************************************************************
Init threads for key rotation */
void
fil_crypt_threads_init();

/*********************************************************************
Clean up key rotation threads resources */
void
fil_crypt_threads_cleanup();

/*********************************************************************
Wait for crypt threads to stop accessing space
@param[in]	space		Tablespace */
void
fil_space_crypt_close_tablespace(
	const fil_space_t*	space);

/*********************************************************************
Get crypt status for a space (used by information_schema)
@param[in]	space		Tablespace
@param[out]	status		Crypt status
return 0 if crypt data present */
void
fil_space_crypt_get_status(
	const fil_space_t*			space,
	struct fil_space_crypt_status_t*	status);

/*********************************************************************
Return crypt statistics
@param[out]	stat		Crypt statistics */
void
fil_crypt_total_stat(
	fil_crypt_stat_t *stat);

/**
Get scrub status for a space (used by information_schema)

@param[in]	space		Tablespace
@param[out]	status		Scrub status
return 0 if data found */
void
fil_space_get_scrub_status(
	const fil_space_t*		space,
	fil_space_scrub_status_t*	status);

//#include "fil0crypt.ic"
#endif /* !UNIV_INNOCHECKSUM */

/**
Verify that post encryption checksum match calculated checksum.
This function should be called only if tablespace contains crypt_data
metadata (this is strong indication that tablespace is encrypted).
Function also verifies that traditional checksum does not match
calculated checksum as if it does page could be valid unencrypted,
encrypted, or corrupted.

@param[in,out]	page		page frame (checksum is temporarily modified)
@param[in]	page_size	page size
@param[in]	space		tablespace identifier
@param[in]	offset		page number
@return true if page is encrypted AND OK, false otherwise */
bool
fil_space_verify_crypt_checksum(
	byte* 			page,
	const page_size_t&	page_size,
	ulint			space,
	ulint			offset)
	MY_ATTRIBUTE((warn_unused_result));

#endif /* fil0crypt_h */
