#ifndef EVENT_ENCRYPTER_H
#define EVENT_ENCRYPTER_H

#include "my_global.h"
#include "my_crypt.h"
#include "rpl_constants.h"
#include "binlog_event.h"

bool encrypt_event(uint32 offs, const Binlog_crypt_data *crypto, uchar* buf, uchar *ebuf, uint buf_len);
bool decrypt_event(uint32 offs, const Binlog_crypt_data *crypto, uchar* buf, uchar *ebuf, uint buf_len);

class Event_encrypter
{
public:
  Event_encrypter()
    : crypto(NULL)
    , ctx(NULL) 
    , event_len(0)
  {}

  int init(IO_CACHE *output_cache, uchar* &header, size_t &buf_len);
  int encrypt_and_write(IO_CACHE *output_cache, const uchar *pos, size_t len);
  int finish(IO_CACHE *output_cache);

  /**
     Encryption data (key, nonce). Only used if ctx != 0.
  */
  Binlog_crypt_data *crypto;

  /**
     Encryption context or 0 if no encryption is needed
  */
  void *ctx;

private:
  int maybe_write_event_len(IO_CACHE *output_cache, uchar *pos, size_t len);
  uint event_len;
};

#endif //EVENT_ENCRYPTER_H
