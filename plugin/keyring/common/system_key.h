#include "i_keyring_key.h"
#include <boost/move/unique_ptr.hpp>

namespace keyring {

class System_key_adapter : public IKey //TODO:Change filename to system_key_adapter
{
public:
  System_key_adapter()
    : key_version(-1)
    , keyring_key(NULL)
  {}

  System_key_adapter(long key_version, IKey *keyring_key)
    : key_version(key_version)
    , keyring_key(keyring_key)
  {}  

  void set_keyring_key(IKey *key, long key_version)
  {
    system_key_data.reset(NULL);
    this->keyring_key = key;
    this->key_version = key_version;
  }
  
  IKey* get_keyring_key()
  {
    return keyring_key;
  }

  // Unless key version is set system_key behaves exactly the same
  // as keyring_key
  //void set_key_version(long key_version)
  //{
    //this->system_key_version = key_version; 
  //}

  long get_key_version() const
  {
    return key_version;
  }

  virtual std::string* get_key_signature() const
  {
    DBUG_ASSERT(keyring_key != NULL);
    return keyring_key->get_key_signature();
  }

  virtual std::string* get_key_type()
  {
    DBUG_ASSERT(keyring_key != NULL);
    return keyring_key->get_key_type();
  }
  virtual std::string* get_key_id()
  {
    DBUG_ASSERT(keyring_key != NULL);
    return keyring_key->get_key_id();
  }
  virtual std::string* get_user_id()
  {
    DBUG_ASSERT(keyring_key != NULL);
    return keyring_key->get_user_id();
  }
  virtual uchar* get_key_data()
  {
    DBUG_ASSERT(keyring_key != NULL);

    if (system_key_data == NULL)
      construct_system_key_data();

    return system_key_data.get();
  }
  virtual size_t get_key_data_size()
  {
    DBUG_ASSERT(keyring_key != NULL);

    if (system_key_data == NULL)
      construct_system_key_data();

    return system_key_data_length;
  }
  virtual size_t get_key_pod_size() const
  {
    DBUG_ASSERT(FALSE);
    return 0;
  }
  virtual uchar* release_key_data()
  {
    DBUG_ASSERT(FALSE);
    return NULL;
    // Data hold by system key should never be released
    // because all system keys just addapters over real keys
    // and all memory allocated by them is managed by themselves
  }
  virtual void xor_data()
  {
    DBUG_ASSERT(FALSE);
  }
  virtual void set_key_data(uchar *key_data, size_t key_data_size)
  {
    (void)key_data; (void)key_data_size;
    DBUG_ASSERT(FALSE);
  }
  virtual void set_key_type(const std::string *key_type)
  {
    (void)key_type;
    DBUG_ASSERT(FALSE);
  }
  virtual my_bool load_from_buffer(uchar* buffer, size_t *buffer_position,
                                   size_t input_buffer_size)
  {
    (void)buffer; (void)buffer_position; (void)input_buffer_size;
    DBUG_ASSERT(FALSE);
    return FALSE;
  }
  virtual void store_in_buffer(uchar* buffer, size_t *buffer_position) const
  {
    (void)buffer; (void)buffer_position;
    DBUG_ASSERT(FALSE);
  }
  virtual my_bool is_key_type_valid()
  {
    DBUG_ASSERT(FALSE);
    return FALSE;
  }
  virtual my_bool is_key_id_valid()
  {
    DBUG_ASSERT(FALSE);
    return FALSE;
  }
  virtual my_bool is_key_valid()
  {
    DBUG_ASSERT(FALSE);
    return FALSE;
  }
  virtual my_bool is_key_length_valid()
  {
    DBUG_ASSERT(FALSE);
    return FALSE;
  }

private:
  void construct_system_key_data()
  {
    std::ostringstream system_key_version_ss;
    system_key_version_ss << key_version << ':';
    std::string system_key_version = system_key_version_ss.str(); 

    system_key_data_length = system_key_version.length() +
                             keyring_key->get_key_data_size();

    system_key_data.reset(new uchar[system_key_data_length]);

    //key data stored in system_key_addapter is not xored
    keyring_key->xor_data();
    memcpy(system_key_data.get(), system_key_version.c_str(), system_key_version.length());
    memcpy(system_key_data.get() + system_key_version.length(), keyring_key->get_key_data(),
           keyring_key->get_key_data_size());

    size_t keyring_key_data_size = keyring_key->get_key_data_size();
    uchar *keyring_key_data = keyring_key->release_key_data();

    // Using keyring_key's xor function to xor system key data, next
    // restoring keyring key data
    keyring_key->set_key_data(system_key_data.get(), system_key_data_length);
    keyring_key->xor_data();

    keyring_key->release_key_data();
    keyring_key->set_key_data(keyring_key_data, keyring_key_data_size);

    keyring_key->xor_data();
  }

  boost::movelib::unique_ptr<uchar[]> system_key_data;
  uint system_key_data_length;
  long key_version;

  IKey *keyring_key;
};

} //namespace keyring
