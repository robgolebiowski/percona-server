#include <my_global.h>
#include <gtest/gtest.h>
#include <fstream>
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

  using ::testing::StrEq;

  class Vault_io_test : public ::testing::Test
  {
  protected:
    virtual void SetUp()
    {
//      keyring_file_data_key = PSI_NOT_INSTRUMENTED;
//      keyring_backup_file_data_key = PSI_NOT_INSTRUMENTED;
      correct_token = "2971d426-ec82-6160-594e-63772682f3c9"; //maybe this could be passed as a parameter to unit test ?
      credential_file_url = "./credentials";
      credential_file_was_created = false;
      logger= new Logger(logger);
    }

    virtual void TearDown()
    {
      if (credential_file_was_created)
        std::remove(credential_file_url.c_str());
//      fake_mysql_plugin.name.str= const_cast<char*>("FakeKeyringPlugin");
//      fake_mysql_plugin.name.length= strlen("FakeKeyringPlugin");
      delete logger;
    }

  protected:
    void create_credentials_file_with_correct_token();

//    st_plugin_int fake_mysql_plugin;
    ILogger *logger;
    std::string correct_token;
    std::string credential_file_url;
    bool credential_file_was_created;
  };

  void Vault_io_test::create_credentials_file_with_correct_token()
  {
    std::remove(credential_file_url.c_str());
    std::ofstream myfile;
    myfile.open(credential_file_url.c_str());
    myfile << correct_token;
    myfile.close();
    credential_file_was_created = true;
  }

  TEST_F(Vault_io_test, InitWithInvalidToken)
  {
    ILogger *logger= new Mock_logger();
    Vault_io vault_io(logger);

    std::string token_in_file("What-a-pretty-token");

    std::remove(credential_file_url.c_str());
    std::ofstream myfile;
    myfile.open(credential_file_url.c_str());
    myfile << token_in_file;
    myfile.close();
    //***

    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Vault has returned the following errors: [\"permission denied\"]")));
    ISerialized_object *serialized_keys= NULL;
    EXPECT_EQ(vault_io.get_serialized_object(&serialized_keys), TRUE);

    std::remove(credential_file_url.c_str());
    delete logger;
  }

  TEST_F(Vault_io_test, GetSerializedObjectWithTwoKeys)
  {
    Vault_io vault_io_for_storing(logger);
    create_credentials_file_with_correct_token();

    EXPECT_EQ(vault_io_for_storing.init(&credential_file_url), FALSE);

    //First Add Two keys into Vault
    Vault_key key1("key1", "AES", "Robert", "Robi", 4);
    EXPECT_STREQ(key1.get_key_signature()->c_str(), "4_key16_Robert");
    key1.set_key_operation(STORE_KEY);
    EXPECT_EQ(vault_io_for_storing.flush_to_storage(&key1), FALSE);
    Vault_key key2("key2", "AES", "Kamil", "Kami", 4);
    EXPECT_STREQ(key2.get_key_signature()->c_str(), "4_key25_Kamil");
    key2.set_key_operation(STORE_KEY);
    EXPECT_EQ(vault_io_for_storing.flush_to_storage(&key2), FALSE);
    //*****

    //Now fetch two keys with separate Vault_io
    Vault_io vault_io_for_fetching(logger);
    EXPECT_EQ(vault_io_for_fetching.init(&credential_file_url), FALSE);

    ISerialized_object *serialized_keys= NULL;
    EXPECT_EQ(vault_io_for_fetching.get_serialized_object(&serialized_keys), FALSE);
    IKey *key1_loaded= NULL;
    ASSERT_TRUE(serialized_keys != NULL);
    EXPECT_EQ(serialized_keys->has_next_key(), TRUE);
    serialized_keys->get_next_key(&key1_loaded);
    EXPECT_STREQ(key1_loaded->get_key_signature()->c_str(), "4_key16_Robert");
    IKey *key2_loaded= NULL;
    delete key1_loaded;
    EXPECT_EQ(serialized_keys->has_next_key(), TRUE);
    serialized_keys->get_next_key(&key2_loaded);
    EXPECT_STREQ(key2_loaded->get_key_signature()->c_str(), "4_key25_Kamil");
    delete key2_loaded;
    EXPECT_EQ(serialized_keys->has_next_key(), FALSE);
    delete serialized_keys;

    //Now remove the keys
    key1.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io_for_storing.flush_to_storage(&key1), FALSE);
    key2.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io_for_storing.flush_to_storage(&key2), FALSE);
  }

  TEST_F(Vault_io_test, RetrieveKeyTypeAndValue)
  {
    Vault_io vault_io(logger);
    create_credentials_file_with_correct_token();
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    Vault_key key_to_store("key1", "AES", "rob", "Robi", 4);
    key_to_store.set_key_operation(STORE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key_to_store), FALSE);

    Vault_key key("key1", NULL, "rob", NULL, 0);
    EXPECT_EQ(vault_io.retrieve_key_type_and_value(&key), FALSE);
    EXPECT_STREQ(key.get_key_signature()->c_str(), "4_key13_rob");
    ASSERT_TRUE(memcmp(key.get_key_data(), "Robi", key.get_key_data_size()) == 0);
    EXPECT_STREQ("AES", key.get_key_type()->c_str());

    key_to_store.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key_to_store), FALSE);
  }

  TEST_F(Vault_io_test, FlushAndRemoveSingleKey)
  {
    Vault_io vault_io(logger);
    create_credentials_file_with_correct_token();
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);
    Vault_key key("key1", "AES", "rob", "Robi", 4);
    key.set_key_operation(STORE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key), FALSE);
    key.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key), FALSE);
  }

  TEST_F(Vault_io_test, FlushKeyRetrieveDeleteInit)
  {
    Vault_io vault_io(logger);
    create_credentials_file_with_correct_token();
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);
    Vault_key key("key1", "AES", "rob", "Robi", 4);
    key.set_key_operation(STORE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key), FALSE);
    Vault_key key1_id("key1", NULL, "rob", NULL, 0);
    EXPECT_EQ(vault_io.retrieve_key_type_and_value(&key1_id), FALSE);
    EXPECT_STREQ(key1_id.get_key_signature()->c_str(), "4_key13_rob");
    ASSERT_TRUE(memcmp(key1_id.get_key_data(), "Robi", key1_id.get_key_data_size()) == 0);
    EXPECT_STREQ("AES", key1_id.get_key_type()->c_str());
    key.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key), FALSE);
    Vault_io vault_io2(logger); //do I need this ?
    EXPECT_EQ(vault_io2.init(&credential_file_url), FALSE);
    ISerialized_object *serialized_keys= NULL;
    EXPECT_EQ(vault_io2.get_serialized_object(&serialized_keys), FALSE);
    ASSERT_TRUE(serialized_keys == NULL); //no keys
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
