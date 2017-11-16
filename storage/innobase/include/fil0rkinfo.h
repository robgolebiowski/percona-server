#ifndef fil0rkinfo_h
#define fil0rkinfo_h

//#ifndef UNIV_INNOCHECKSUM

#define CRYPT_SCHEME_UNENCRYPTED 0
#define CRYPT_SCHEME_1 1

struct Rotated_keys_info
{
   Rotated_keys_info()
     : rk_encryption_key_is_missing(false)
     , page0_has_crypt_data(false)
     , rotated_keys_min_key_version(0)
     , type(CRYPT_SCHEME_UNENCRYPTED)
   {}
   bool rk_encryption_key_is_missing; // initlialized in dict_mem_table_create
   bool page0_has_crypt_data;
   uint rotated_keys_min_key_version;
   uint type;

   bool is_encryption_in_progress()
   {
     return rotated_keys_min_key_version == 0 && type != CRYPT_SCHEME_UNENCRYPTED;
   }
};

//#endif // UNIV_INNOCHECKSUM

#endif
