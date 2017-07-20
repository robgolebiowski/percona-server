#include "my_global.h"
#include "my_crypt.h"

  static int maybe_write_event_len(IO_CACHE *file, uchar *pos, size_t len, uint &event_len)
  {
    if (len && event_len)
    {
      DBUG_ASSERT(len >= EVENT_LEN_OFFSET);
      //if (write_internal(pos + EVENT_LEN_OFFSET - 4, 4))
      if (my_b_safe_write(file, pos + EVENT_LEN_OFFSET - 4, 4)) //TODO:Robert:Co to jest? - Zakodowana część, która później jest przesunięta. pos jest przesunięte o 4 w funkcji rite_header!! - To jest odtworzenie timestampu, który wcześniej był przesunięty w miejsce event_len - madness ?
        return 1;
      int4store(pos + EVENT_LEN_OFFSET - 4, event_len); //TODO:Robert:Tu jest zapisanie event_len do bufora, które później jest zapisane do pliku
      event_len= 0;
    }
    return 0;
  }


  static int encrypt_and_write(IO_CACHE *file, const uchar *pos, size_t len, uint &event_len, void *ctx)
  {
    //return 1;
    //TODO:Robert:Temporary disabling encryption, I am currently only interested in binlog events
    
    uchar *dst= 0;
    size_t dstsize= 0;
    //uint elen;

    //if (crypto != NULL && crypto->scheme)
    if(ctx)
    {
      dstsize= my_aes_crypt_get_size(MY_AES_ECB, len);
      if (!(dst= (uchar*)my_safe_alloca(dstsize, 512)))
        return 1;

         //if ((dstlen = my_aes_decrypt(src + 4, true_data_len - 4, dst + 4, 
                             //crypto_data->key, crypto_data->key_length, my_aes_128_ecb, NULL)) < 0)

      uint dstlen;
      if (my_aes_crypt_update(ctx, pos, len, dst, &dstlen))
        goto err;

      //if (encryption_ctx_update(ctx, pos, len, dst, &dstlen))
        //goto err;


      //if ((elen = my_aes_encrypt(pos, len, dst, crypto->key,
                     //crypto->key_length, my_aes_128_ecb, NULL[>crypto->get_iv()<]) < 0))
        //goto err;

      if (maybe_write_event_len(file, dst, dstlen, event_len))
        return 1;
      pos= dst;
      len= dstlen;


      //dstsize= encryption_encrypted_length(len, ENCRYPTION_KEY_SYSTEM_DATA,
                                           //crypto->key_version);
      //if (!(dst= (uchar*)my_safe_alloca(dstsize, 512)))
        //return 1;

      //if (encryption_ctx_update(ctx, pos, len, dst, &dstlen))
        //goto err;
      //if (maybe_write_event_len(dst, dstlen))
        //return 1;
      //pos= dst;
      //len= dstlen;
    }
    else
    {
      dst = 0;
    }

    if (my_b_safe_write(file, pos, len))
      goto err;

    //if (my_b_safe_write(file, pos, len))
      //goto err;
    //bytes_written+= len; //TODO:Robert: This is what I am missing
    //TODO:Robert:This is the old part
    //if (write_internal(pos, len))
      //goto err;

    my_safe_afree(dst, dstsize, 512);
    return 0;
  err:
    my_safe_afree(dst, dstsize, 512);
    return 1;
    
  }
