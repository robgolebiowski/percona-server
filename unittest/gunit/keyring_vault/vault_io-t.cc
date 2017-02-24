#include <my_global.h>
#include <gtest/gtest.h>
#include "mock_logger.h"
#include "vault_io.h"
#include <string.h>
#include <curl/curl.h>

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
