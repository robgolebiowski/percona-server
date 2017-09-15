#include <my_global.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <system_keys_container.h>
#include "mock_logger.h"

#if !defined(MERGE_UNITTESTS)
#ifdef HAVE_PSI_INTERFACE
namespace keyring
{
  PSI_memory_key key_memory_KEYRING = PSI_NOT_INSTRUMENTED;
  PSI_memory_key key_LOCK_keyring = PSI_NOT_INSTRUMENTED;
}
#endif
//mysql_rwlock_t LOCK_keyring;
#endif

namespace keyring__system_keys_container_unittest
{
  using namespace keyring;
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
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.update_if_system_key(key1);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);
    IKey* fetched_key= sys_keys_container.fetch_system_key(&key_id);

    ASSERT_TRUE(fetched_key != NULL);
    std::string expected_key_signature= "percona_binlog";
    EXPECT_STREQ(fetched_key->get_key_signature()->c_str(), expected_key_signature.c_str());
    EXPECT_EQ(fetched_key->get_key_signature()->length(), expected_key_signature.length());
    uchar* key_data_fetched= fetched_key->get_key_data();
    size_t key_data_fetched_size= fetched_key->get_key_data_size();
    EXPECT_STREQ(key_data1.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
    ASSERT_TRUE(key_data1.length()+1 == key_data_fetched_size);

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
    IKey* fetched_key= sys_keys_container.fetch_system_key(&key_id);

    ASSERT_TRUE(fetched_key != NULL);
    std::string expected_key_signature= "percona_binlog";
    EXPECT_STREQ(fetched_key->get_key_signature()->c_str(), expected_key_signature.c_str());
    EXPECT_EQ(fetched_key->get_key_signature()->length(), expected_key_signature.length());
    uchar* key_data_fetched= fetched_key->get_key_data();
    size_t key_data_fetched_size= fetched_key->get_key_data_size();
    EXPECT_STREQ(key_data2.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
    ASSERT_TRUE(key_data2.length()+1 == key_data_fetched_size);

    delete key1;
    delete key2;
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
    IKey* fetched_key= sys_keys_container.fetch_system_key(&key_id);

    ASSERT_TRUE(fetched_key != NULL);
    std::string expected_key_signature= "percona_binlog";
    EXPECT_STREQ(fetched_key->get_key_signature()->c_str(), expected_key_signature.c_str());
    EXPECT_EQ(fetched_key->get_key_signature()->length(), expected_key_signature.length());
    uchar* key_data_fetched= fetched_key->get_key_data();
    size_t key_data_fetched_size= fetched_key->get_key_data_size();
    EXPECT_STREQ(key_data1.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
    ASSERT_TRUE(key_data1.length()+1 == key_data_fetched_size);

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
    IKey* fetched_key= sys_keys_container.fetch_system_key(&key_id);

    ASSERT_TRUE(fetched_key != NULL);
    std::string expected_key_signature= "percona_binlog";
    EXPECT_STREQ(fetched_key->get_key_signature()->c_str(), expected_key_signature.c_str());
    EXPECT_EQ(fetched_key->get_key_signature()->length(), expected_key_signature.length());
    uchar* key_data_fetched= fetched_key->get_key_data();
    size_t key_data_fetched_size= fetched_key->get_key_data_size();
    EXPECT_STREQ(key_data3.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
    ASSERT_TRUE(key_data3.length()+1 == key_data_fetched_size);

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

    Key key_id("percona_binlog:0", NULL, NULL, NULL,0);
    IKey* fetched_key= sys_keys_container.fetch_system_key(&key_id);

    ASSERT_TRUE(fetched_key == NULL);

    delete key1;
    delete key2;
    delete key3;
  }
} //namespace keyring__system_keys_container_unittest

