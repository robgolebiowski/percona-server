#include <my_global.h>
#include "item_cmpfunc.h"

class Item_func_rotate_system_key : public Item_bool_func
{
public:
  Item_func_rotate_system_key(const POS &pos, Item *system_key_id)
    : Item_bool_func(pos, system_key_id)
  {
    null_value= false;
  }

public:
  virtual longlong val_int();
  virtual const char *func_name() const
  { return "rotate_system_key"; }
  virtual bool itemize(Parse_context *pc, Item **res);
  virtual bool fix_fields(THD *, Item **);

protected:
  virtual bool calc_value(const String *arg);
};

