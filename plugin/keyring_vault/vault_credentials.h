#ifndef MYSQL_VAULT_CREDENTIALS
#define MYSQL_VAULT_CREDENTIALS

#include <my_global.h>
#include <map>
#include <string>

namespace keyring
{
  template <class T> class Secure_allocator : public std::allocator<T>
  {
  public:

    template<class U> struct rebind { typedef Secure_allocator<U> other; };
    Secure_allocator() throw() {}
    //TODO: Add alocating memory with keyring malloc
    Secure_allocator(const Secure_allocator& secure_allocator) : std::allocator<T>(secure_allocator)
       {}
    template <class U> Secure_allocator(const Secure_allocator<U>&) throw() {}

    void deallocate(T *p, size_t n)
    {
//      SecureZeroMemory((void *)p, num);
//      TODO: add memset
      std::allocator<T>::deallocate(p, n);
    }
  };

  typedef std::basic_string<char, std::char_traits<char>, Secure_allocator<char> > SecureString;
  typedef std::map<SecureString, SecureString> Vault_credentials;
} //namespace keyring

#endif //MYSQL_VAULT_CREDENTIALS
