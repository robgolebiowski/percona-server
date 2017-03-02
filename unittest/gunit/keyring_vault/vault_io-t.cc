#include <my_global.h>
#include <gtest/gtest.h>
#include "mock_logger.h"
#include "vault_io.h"
#include <string.h>
#include <curl/curl.h>

#if defined(HAVE_PSI_INTERFACE)
namespace keyring
{
  PSI_memory_key key_memory_KEYRING = PSI_NOT_INSTRUMENTED;
//  PSI_memory_key key_LOCK_keyring = PSI_NOT_INSTRUMENTED;
}
#endif

namespace keyring__vault_io_unittest
{
  using namespace keyring;

  class Vault_io_test : public ::testing::Test
  {
  protected:
    virtual void SetUp()
    {
//      keyring_file_data_key = PSI_NOT_INSTRUMENTED;
//      keyring_backup_file_data_key = PSI_NOT_INSTRUMENTED;
      logger= new Logger(logger);
    }

    virtual void TearDown()
    {
//      fake_mysql_plugin.name.str= const_cast<char*>("FakeKeyringPlugin");
//      fake_mysql_plugin.name.length= strlen("FakeKeyringPlugin");
      delete logger;
    }

  protected:
//    st_plugin_int fake_mysql_plugin;
    ILogger *logger;
  };

  TEST_F(Vault_io_test, InitWithNotExisitingKeyringFile)
  {
    std::string file_name("./some_funny_name");
    Vault_io vault_io(logger);
    std::string sasa="sasa";
    EXPECT_EQ(vault_io.init(&sasa), FALSE);
//    remove(file_name.c_str());
//    EXPECT_EQ(buffered_io.init(&file_name),0);
//    ISerialized_object *serialized_object= NULL;
//
//    EXPECT_EQ(buffered_io.get_serialized_object(&serialized_object), 0);
    //The keyring file is new so no keys should be available
//    ASSERT_TRUE(serialized_object == NULL);

//    remove(file_name.c_str());
  }

  TEST_F(Vault_io_test, GetSerializedObjectWithTwoKeys)
  {
    Vault_io vault_io(logger);
    std::string sasa="sasa";
    EXPECT_EQ(vault_io.init(&sasa), FALSE);
    ISerialized_object *serialized_keys= NULL;
    EXPECT_EQ(vault_io.get_serialized_object(&serialized_keys), FALSE);
    IKey *key_loaded= NULL;
    EXPECT_EQ(serialized_keys->has_next_key(), TRUE);
    serialized_keys->get_next_key(&key_loaded);
    EXPECT_STREQ(key_loaded->get_key_signature()->c_str(), "4key13rob");
    EXPECT_EQ(serialized_keys->has_next_key(), TRUE);
    serialized_keys->get_next_key(&key_loaded);
    EXPECT_STREQ(key_loaded->get_key_signature()->c_str(), "4key23rob");
    EXPECT_EQ(serialized_keys->has_next_key(), FALSE);
    //    remove(file_name.c_str());
    //    EXPECT_EQ(buffered_io.init(&file_name),0);
    //    ISerialized_object *serialized_object= NULL;
    //
    //    EXPECT_EQ(buffered_io.get_serialized_object(&serialized_object), 0);
    //The keyring file is new so no keys should be available
    //    ASSERT_TRUE(serialized_object == NULL);

    //    remove(file_name.c_str());
  }

  TEST_F(Vault_io_test, RetrieveKeyTypeAndValue)
  {
    Vault_io vault_io(logger);
    std::string sasa="sasa";
    EXPECT_EQ(vault_io.init(&sasa), FALSE);
    Vault_key key("key1", NULL, "rob", NULL, 0);
    EXPECT_EQ(vault_io.retrieve_key_type_and_value(&key), FALSE);
    EXPECT_STREQ(key.get_key_signature()->c_str(), "4key13rob");
    ASSERT_TRUE(memcmp(key.get_key_data(), "Robi", key.get_key_data_size()) == 0);
    EXPECT_STREQ("AES", key.get_key_type()->c_str());
  }

  TEST_F(Vault_io_test, FlushSingleKey)
  {
    Vault_io vault_io(logger);
    std::string sasa="sasa";
    EXPECT_EQ(vault_io.init(&sasa), FALSE);
    Vault_key key("key1", "AES", "rob", "Robi", 4);
    EXPECT_EQ(vault_io.flush_to_storage(&key), FALSE);
  }

} //namespace keyring__file_io_unittest

int main(int argc, char **argv) {
//  if (mysql_rwlock_init(key_LOCK_keyring, &LOCK_keyring))
//    return TRUE;
  curl_global_init(CURL_GLOBAL_DEFAULT);
  ::testing::InitGoogleTest(&argc, argv);
  int ret= RUN_ALL_TESTS();
  curl_global_cleanup();
  return ret;
}
