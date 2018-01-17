#include <my_global.h>
#include "item_keyring_func.h"
#include <mysql/service_mysql_keyring.h>
#include "sql_class.h"           // THD

bool Item_func_rotate_system_key::itemize(Parse_context *pc, Item **res)
{
  if (skip_itemize(res))
    return false;
  if (Item_bool_func::itemize(pc, res))
    return true;
  pc->thd->lex->set_stmt_unsafe(LEX::BINLOG_STMT_UNSAFE_UDF);
  pc->thd->lex->safe_to_cache_query= false;
  return false;
}

longlong Item_func_rotate_system_key::val_int()
{
  DBUG_ASSERT(fixed);

  if (args[0]->result_type() != STRING_RESULT) // String argument expected
    return 0;

  String buffer;
  String *arg_str= args[0]->val_str(&buffer);

  if (!arg_str) // Out-of memory happened. The error has been reported.
    return 0;   // Or: the underlying field is NULL

  return calc_value(arg_str) ? 1 : 0;
}

bool Item_func_rotate_system_key::calc_value(const String *arg)
{
  //in6_addr ipv6_address;
  //return str_to_ipv6(arg->ptr(), arg->length(), &ipv6_address);
  if (memcmp("percona_binlog", arg->ptr(), arg->length()) != 0)
    return false;
  
  
  return !(my_key_generate(arg->ptr(), "AES", NULL, 16));
}
