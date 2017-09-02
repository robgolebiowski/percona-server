#include "my_global.h"
#include "my_crypt.h"

  static int maybe_write_event_len(IO_CACHE *file, uchar *pos, size_t len, uint &event_len)
  {
    if (len && event_len)
    {
      DBUG_ASSERT(len >= EVENT_LEN_OFFSET);
      if (my_b_safe_write(file, pos + EVENT_LEN_OFFSET - 4, 4)) //TODO:Robert:Co to jest? - Zakodowana część, która później jest przesunięta. pos jest przesunięte o 4 w funkcji rite_header!! - To jest odtworzenie timestampu, który wcześniej był przesunięty w miejsce event_len - madness ?
        return 1;
      int4store(pos + EVENT_LEN_OFFSET - 4, event_len); //TODO:Robert:Tu jest zapisanie event_len do bufora, które później jest zapisane do pliku
      event_len= 0;
    }
    return 0;
  }

  static int encrypt_and_write(IO_CACHE *file, const uchar *pos, size_t len, uint &event_len, void *ctx)
  {
    uchar *dst= 0;
    size_t dstsize= 0;

    if(ctx)
    {
      dstsize= my_aes_crypt_get_size(MY_AES_ECB, len);
      if (!(dst= (uchar*)my_safe_alloca(dstsize, 512)))
        return 1;

      uint dstlen;
      if (my_aes_crypt_update(ctx, pos, len, dst, &dstlen))
        goto err;

      if (maybe_write_event_len(file, dst, dstlen, event_len))
        return 1;
      pos= dst;
      len= dstlen;
    }
    else
    {
      dst = 0;
    }

    if (my_b_safe_write(file, pos, len))
      goto err;

    my_safe_afree(dst, dstsize, 512);
    return 0;
  err:
    my_safe_afree(dst, dstsize, 512);
    return 1;
    
  }

  static int init_event_crypt(IO_CACHE *output_cache, Binlog_crypt_data *crypto, uchar* &header, void *ctx, size_t &buf_len, uint &event_len)
  {
    uchar iv[BINLOG_IV_LENGTH];
    crypto->set_iv(iv, my_b_safe_tell(output_cache));

    int res= 0;

    if ((res= my_aes_crypt_init(ctx, MY_AES_CBC, ENCRYPTION_FLAG_ENCRYPT | ENCRYPTION_FLAG_NOPAD,
                               crypto->key, crypto->key_length, iv, sizeof(iv))))
      return res;

    DBUG_ASSERT(buf_len >= LOG_EVENT_HEADER_LEN);
    event_len= uint4korr(header + EVENT_LEN_OFFSET); //event_len jest z checksum, event_len_p jest bez checksumu
    DBUG_ASSERT(event_len >= buf_len);
    memcpy(header + EVENT_LEN_OFFSET, header, 4);
    header+= 4;
    buf_len-= 4;

    return res;
  }

  static int finish_event_crypt(IO_CACHE *output_cache, uint event_len, void *ctx)
  {
    uint dstlen;
    uchar dst[MY_CRYPT_AES_BLOCK_SIZE*2];
    if (my_aes_crypt_finish(ctx, dst, &dstlen) || maybe_write_event_len(output_cache, dst, dstlen, event_len) ||
        my_b_safe_write(output_cache, dst, dstlen))
      return 1;
    return 0;
  }
