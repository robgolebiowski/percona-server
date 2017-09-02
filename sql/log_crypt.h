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
