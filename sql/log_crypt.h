#include "my_global.h"
#include "my_crypt.h"
#include "rpl_constants.h"
#include <boost/move/unique_ptr.hpp>
#include "sql_string.h"
#include "binlog_event.h"

int maybe_write_event_len(IO_CACHE *file, uchar *pos, size_t len, uint &event_len);
int encrypt_and_write(IO_CACHE *file, const uchar *pos, size_t len, uint &event_len, void *ctx);
int init_event_crypt(IO_CACHE *output_cache, Binlog_crypt_data *crypto, uchar* &header, void *ctx, size_t &buf_len, uint &event_len);
int finish_event_crypt(IO_CACHE *output_cache, uint event_len, void *ctx);
bool encrypt_event(uint32 offs, const Binlog_crypt_data *crypto, uchar* buf, uchar *ebuf, uint buf_len);
bool decrypt_event(uint32 offs, const Binlog_crypt_data *crypto, uchar* buf, uchar *ebuf, uint buf_len);
