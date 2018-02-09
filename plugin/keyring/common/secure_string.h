#ifndef MYSQL_KEYRING_SECURE_STRING
#define MYSQL_KEYRING_SECURE_STRING

#include "keyring_memory.h"
#include <sstream>

namespace keyring
{
  typedef std::basic_string<char, std::char_traits<char>, Secure_allocator<char> > Secure_string;
  typedef std::basic_ostringstream<char, std::char_traits<char>, Secure_allocator<char> > Secure_ostringstream;
  typedef std::basic_istringstream<char, std::char_traits<char>, Secure_allocator<char> > Secure_istringstream;
}

#endif // MYSQL_KEYRING_SECURE_STRING
