#include <my_global.h>
#include <gtest/gtest.h>
#include "mock_logger.h"
#include "vault_parser.h"

#if defined(HAVE_PSI_INTERFACE)
namespace keyring
{
  PSI_memory_key key_memory_KEYRING = PSI_NOT_INSTRUMENTED;
//  PSI_memory_key key_LOCK_keyring = PSI_NOT_INSTRUMENTED;
}
#endif

namespace keyring__vault_parser_unittest
{
  using namespace keyring;

  using ::testing::StrEq;

  class Vault_parser_test : public ::testing::Test
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

  TEST_F(Vault_parser_test, ParseKeySignature)
  {
    std::string key_signature("4key13rob");
    Vault_parser vault_parser;
    std::string key_parameters[2];
    vault_parser.parse_key_signature(&key_signature, key_parameters);
    EXPECT_STREQ(key_parameters[0].c_str(), "key1");
    EXPECT_STREQ(key_parameters[1].c_str(), "rob");
  }

  TEST_F(Vault_parser_test, ParseKeySignature2)
  {
    std::string key_signature("4key16Robert");
    Vault_parser vault_parser;
    std::string key_parameters[2];
    vault_parser.parse_key_signature(&key_signature, key_parameters);
    EXPECT_STREQ(key_parameters[0].c_str(), "key1");
    EXPECT_STREQ(key_parameters[1].c_str(), "Robert");
  }

  TEST_F(Vault_parser_test, ParseVaultPayload)
  {
    std::string payload("{\"request_id\":\"724a5ad6-7ee3-7950-879a-488a261a03ec\","
                        "\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,"
                        "\"data\":{\"keys\":[\"4key13rob\",\"4key23rob\"]},\"wrap_info"
                        "\":null,\"warnings\":null,\"auth\":null}");
    Vault_keys_list keys;
    Vault_parser vault_parser;
    EXPECT_EQ(vault_parser.parse_keys(&payload, &keys), FALSE);
    EXPECT_EQ(keys.size(), 2);
    EXPECT_EQ(keys.has_next_key(), TRUE);
    IKey *key_loaded= NULL;
    EXPECT_EQ(keys.get_next_key(&key_loaded), FALSE);
    EXPECT_STREQ(key_loaded->get_key_signature()->c_str(), "4key13rob");
    EXPECT_EQ(keys.has_next_key(), TRUE);
    delete key_loaded;
    key_loaded = NULL;
    EXPECT_EQ(keys.get_next_key(&key_loaded), FALSE);
    EXPECT_STREQ(key_loaded->get_key_signature()->c_str(), "4key23rob");
    EXPECT_EQ(keys.has_next_key(), FALSE);
  }

  TEST_F(Vault_parser_test, ParseKeyData)
  {
    std::string payload("{\"request_id\":\"77626d44-edbd-c82f-8220-c3c6b13ef2e1\","
                        "\"lease_id\":\"\",\"renewable\":false,\"lease_duration\""
                        ":2764800,\"data\":{\"type\":\"AES\",\"value\":\"Robi\"},"
                        "\"wrap_info\":null,\"warnings\":null,\"auth\":null}");

    Vault_parser vault_parser;
    Vault_key key("key1", NULL, "rob", NULL, 0);
    EXPECT_EQ(vault_parser.parse_key_data(&payload, &key), FALSE);
    EXPECT_STREQ(key.get_key_signature()->c_str(), "4key13rob");
    ASSERT_TRUE(memcmp(key.get_key_data(), "Robi", key.get_key_data_size()) == 0);
    EXPECT_STREQ("AES", key.get_key_type()->c_str());
  }
} //namespace keyring__file_io_unittest




















int main(int argc, char **argv) {
//  if (mysql_rwlock_init(key_LOCK_keyring, &LOCK_keyring))
//    return TRUE;
//  curl_global_init(CURL_GLOBAL_DEFAULT);
  ::testing::InitGoogleTest(&argc, argv);
  int ret= RUN_ALL_TESTS();
//  curl_global_cleanup();
  return ret;
}