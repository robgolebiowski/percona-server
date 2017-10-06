#include <my_global.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <system_keys_container.h>
#include "mock_logger.h"
//#include "plugin/keyring/common/key.h"
#include "keyring_key.h"

#if !defined(MERGE_UNITTESTS) && defined(HAVE_PSI_INTERFACE)
namespace keyring
{
  PSI_memory_key key_memory_KEYRING = PSI_NOT_INSTRUMENTED;
  PSI_memory_key key_LOCK_keyring = PSI_NOT_INSTRUMENTED;
}
#endif

namespace keyring__system_keys_container_unittest
{
  using namespace keyring;
  using keyring::Key;
  using ::testing::Return;
  using ::testing::InSequence;
  using ::testing::_;
  using ::testing::StrEq;
  using ::testing::DoAll;
  using ::testing::SetArgPointee;

  class System_keys_container_test : public ::testing::Test
  {
  protected:
    System_keys_container sys_keys_container;
  };

  TEST_F(System_keys_container_test, StoreFetch)
  {
    std::string key_data1("system_key_data_1");
    Key *key1 = new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.update_if_system_key(key1);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);
    std::string system_key_id = sys_keys_container.get_latest_key_id_if_system_key(&key_id);
    EXPECT_STREQ(system_key_id.c_str(), "percona_binlog:0");

    delete key1;
  }

  TEST_F(System_keys_container_test, StoreStoreFetch)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:1", "AES", NULL, key_data2.c_str(), key_data2.length()+1);

    sys_keys_container.update_if_system_key(key2);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);
    std::string system_key_id = sys_keys_container.get_latest_key_id_if_system_key(&key_id);
    EXPECT_STREQ(system_key_id.c_str(), "percona_binlog:1");

    delete key1;
    delete key2;
  }

  TEST_F(System_keys_container_test, StoreStoreStoreFetch)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:1", "AES", NULL, key_data2.c_str(), key_data2.length()+1);

    sys_keys_container.update_if_system_key(key2);

    std::string key_data3("system_key_data_3");
    Key *key3= new Key("percona_binlog:2", "AES", NULL, key_data3.c_str(), key_data3.length()+1);

    sys_keys_container.update_if_system_key(key3);


    Key key_id("percona_binlog", NULL, NULL, NULL,0);
    std::string system_key_id = sys_keys_container.get_latest_key_id_if_system_key(&key_id);
    EXPECT_STREQ(system_key_id.c_str(), "percona_binlog:2");

    delete key1;
    delete key2;
    delete key3;
  }


  TEST_F(System_keys_container_test, StoreKeyWithTheSameIdTwice)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:0", "AES", NULL, key_data2.c_str(), key_data2.length()+1);

    sys_keys_container.update_if_system_key(key2);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);
    std::string system_key_id = sys_keys_container.get_latest_key_id_if_system_key(&key_id);
    EXPECT_STREQ(system_key_id.c_str(), "percona_binlog:0");

    delete key1;
    delete key2;
  }

  TEST_F(System_keys_container_test, StoreKeyWithTheSameIdTwiceAndThenWithDifferentOne)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:0", "AES", NULL, key_data2.c_str(), key_data2.length()+1);

    sys_keys_container.update_if_system_key(key2);

    std::string key_data3("system_key_data_3");
    Key *key3= new Key("percona_binlog:1", "AES", NULL, key_data3.c_str(), key_data3.length()+1);

    sys_keys_container.update_if_system_key(key3);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);
    std::string system_key_id = sys_keys_container.get_latest_key_id_if_system_key(&key_id);
    EXPECT_STREQ(system_key_id.c_str(), "percona_binlog:1");

    delete key1;
    delete key2;
    delete key3;
  }

  TEST_F(System_keys_container_test, StoreStoreStoreFetchInvalid)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:1", "AES", NULL, key_data2.c_str(), key_data2.length()+1);

    sys_keys_container.update_if_system_key(key2);

    std::string key_data3("system_key_data_3");
    Key *key3= new Key("percona_binlog:2", "AES", NULL, key_data3.c_str(), key_data3.length()+1);

    sys_keys_container.update_if_system_key(key3);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);
    std::string system_key_id = sys_keys_container.get_latest_key_id_if_system_key(&key_id);
    EXPECT_STREQ(system_key_id.c_str(), "percona_binlog:2");

    delete key1;
    delete key2;
    delete key3;
  }
} //namespace keyring__system_keys_container_unittest

