#include "system_key_adapter.h"

namespace keyring
{
  // Adds key's version to keyring's key data. The resulting system key data looks like this:
  // <key_version>:<keyring key data>
  void System_key_adapter::construct_system_key_data()
  {
    std::ostringstream system_key_data_version_prefix_ss;
    system_key_data_version_prefix_ss << key_version << ':';
    std::string system_key_data_version_prefix = system_key_data_version_prefix_ss.str(); 

    system_key_data_length = system_key_data_version_prefix.length() +
                             keyring_key->get_key_data_size();

    system_key_data.reset(new uchar[system_key_data_length]);

    // need to "de"-xor keying key data to be able to add to it key version prefix 
    keyring_key->xor_data();
    memcpy(system_key_data.get(), system_key_data_version_prefix.c_str(), system_key_data_version_prefix.length());
    memcpy(system_key_data.get() + system_key_data_version_prefix.length(), keyring_key->get_key_data(),
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
} //namespace keyring
