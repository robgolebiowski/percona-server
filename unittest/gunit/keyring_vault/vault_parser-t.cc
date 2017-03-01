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
//    remove(file_name.c_str());
//    EXPECT_EQ(buffered_io.init(&file_name),0);
//    ISerialized_object *serialized_object= NULL;
//
//    EXPECT_EQ(buffered_io.get_serialized_object(&serialized_object), 0);
    //The keyring file is new so no keys should be available
//    ASSERT_TRUE(serialized_object == NULL);

//    remove(file_name.c_str());
  }

  TEST_F(Vault_parser_test, ParseVaultPayload)
  {
    std::string payload("{\"request_id\":\"724a5ad6-7ee3-7950-879a-488a261a03ec\","
                        "\"lease_id\":\"\",\"renewable\":false,\"lease_duration\":0,"
                        "\"data\":{\"keys\":[\"4key13rob\",\"4key23rob\"]},\"wrap_info"
                        "\":null,\"warnings\":null,\"auth\":null}");
    std::list<IKey*> keys;
    Vault_parser vault_parser;
    size_t keys_pod_size;
//my_bool parse_keys(std::string *payload, std::list<IKey*> *keys, size_t *keys_pod_size)
    vault_parser.parse_keys(&payload, &keys, &keys_pod_size);
    EXPECT_EQ(keys.size(), 2);
    std::list<IKey*>::iterator keys_iter = keys.begin();
    EXPECT_STREQ((*keys_iter)->get_key_signature()->c_str(), "key1rob");
    size_t parsed_keys_pod_size = (*keys_iter)->get_key_pod_size();
    keys_iter++;
    EXPECT_STREQ((*keys_iter)->get_key_signature()->c_str(), "key2rob");
    parsed_keys_pod_size += (*keys_iter)->get_key_pod_size();
    EXPECT_EQ(parsed_keys_pod_size, keys_pod_size);
//    EXPECT_STREQ(key_parameters[0].c_str(), "key1");
//    EXPECT_STREQ(key_parameters[1].c_str(), "rob");
//    remove(file_name.c_str());
//    EXPECT_EQ(buffered_io.init(&file_name),0);
//    ISerialized_object *serialized_object= NULL;
//
//    EXPECT_EQ(buffered_io.get_serialized_object(&serialized_object), 0);
    //The keyring file is new so no keys should be available
//    ASSERT_TRUE(serialized_object == NULL);

//    remove(file_name.c_str());
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