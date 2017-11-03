#include <my_global.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <system_keys_container.h>
#include "mock_logger.h"
//#include "plugin/keyring/common/key.h"
#include "keyring_key.h"
#include <sstream>

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
  using ::testing::StrEq;

  class System_keys_container_test : public ::testing::Test
  {
  protected:
    System_keys_container sys_keys_container;
  };

  TEST_F(System_keys_container_test, StoreFetchPBkeyStoreFetchSystemKey)
  {
    std::string key_data1("system_key_data_1");
    Key *key1 = new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    key1->xor_data();

    sys_keys_container.store_or_update_if_system_key(key1);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);

    IKey* system_key = sys_keys_container.get_latest_key_if_system_key(&key_id);

    std::string key_data_with_version = "0:" + key_data1;
    Key key(system_key->get_key_id()->c_str(), system_key->get_key_type()->c_str(), system_key->get_user_id()->c_str(),
            system_key->get_key_data(), system_key->get_key_data_size());
    key.xor_data();        
    uchar* key_data_fetched= key.get_key_data();
    size_t key_data_fetched_size= key.get_key_data_size();
    EXPECT_STREQ(key.get_key_id()->c_str(), "percona_binlog:0");
    EXPECT_STREQ(key_data_with_version.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", key.get_key_type()->c_str());
    ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

    std::string key_data2("system_key_data_2");
    Key *key_innodb_sk = new Key("percona_innodb123:0", "AES", NULL, key_data2.c_str(), key_data2.length()+1);
    key_innodb_sk->xor_data();

    sys_keys_container.store_or_update_if_system_key(key_innodb_sk);

    Key innodb_key_id("percona_innodb123", NULL, NULL, NULL,0);

    system_key = sys_keys_container.get_latest_key_if_system_key(&innodb_key_id);

    ASSERT_TRUE(system_key != NULL);

    key_data_with_version = "0:" + key_data2;
    Key key_2(system_key->get_key_id()->c_str(), system_key->get_key_type()->c_str(), system_key->get_user_id()->c_str(),
            system_key->get_key_data(), system_key->get_key_data_size());
    key_2.xor_data();        
    key_data_fetched= key_2.get_key_data();
    key_data_fetched_size= key_2.get_key_data_size();
    EXPECT_STREQ(key_2.get_key_id()->c_str(), "percona_innodb123:0");
    EXPECT_STREQ(key_data_with_version.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", key_2.get_key_type()->c_str());
    ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

    delete key1;
    delete key_innodb_sk;
  }

  TEST_F(System_keys_container_test, StoreKey1StoreKey1FetchStoreKey2StoreKey2Fetch)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    key1->xor_data();

    sys_keys_container.store_or_update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:1", "AES", NULL, key_data2.c_str(), key_data2.length()+1);
    key2->xor_data();

    sys_keys_container.store_or_update_if_system_key(key2);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);

    IKey* system_key = sys_keys_container.get_latest_key_if_system_key(&key_id);

    Key key(system_key->get_key_id()->c_str(), system_key->get_key_type()->c_str(), system_key->get_user_id()->c_str(),
            system_key->get_key_data(), system_key->get_key_data_size());
    key.xor_data();        
    uchar* key_data_fetched= key.get_key_data();
    size_t key_data_fetched_size= key.get_key_data_size();
    std::string key_data_with_version = "1:" + key_data2;
    EXPECT_STREQ(key.get_key_id()->c_str(), "percona_binlog:1");
    EXPECT_STREQ(key_data_with_version.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", key.get_key_type()->c_str());
    ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

    std::string key_data3("1234XXXYYYZZZZ5335");
    Key *key1_sk= new Key("percona_system_key:0", "AES", NULL, key_data3.c_str(), key_data3.length()+1);
    key1_sk->xor_data();

    sys_keys_container.store_or_update_if_system_key(key1_sk);

    std::string key_data4("CCCSADSDa___DFsdfk0001___");
    Key *key2_sk= new Key("percona_system_key:1", "AES", NULL, key_data4.c_str(), key_data4.length()+1);
    key2_sk->xor_data();

    sys_keys_container.store_or_update_if_system_key(key2_sk);

    Key system_key_id("percona_system_key", NULL, NULL, NULL,0);

    system_key = sys_keys_container.get_latest_key_if_system_key(&system_key_id);

    Key key_sk(system_key->get_key_id()->c_str(), system_key->get_key_type()->c_str(), system_key->get_user_id()->c_str(),
               system_key->get_key_data(), system_key->get_key_data_size());
    key_sk.xor_data();        
    key_data_fetched= key_sk.get_key_data();
    key_data_fetched_size= key_sk.get_key_data_size();
    key_data_with_version = "1:" + key_data4;
    EXPECT_STREQ(key_sk.get_key_id()->c_str(), "percona_system_key:1");
    EXPECT_STREQ(key_data_with_version.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", key_sk.get_key_type()->c_str());
    ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

    delete key1;
    delete key2;
    delete key1_sk;
    delete key2_sk;
  }

 
  TEST_F(System_keys_container_test, StoreStoreStoreFetch)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_key:0:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    key1->xor_data();

    sys_keys_container.store_or_update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_key:0:1", "AES", NULL, key_data2.c_str(), key_data2.length()+1);
    key2->xor_data();

    sys_keys_container.store_or_update_if_system_key(key2);

    std::string key_data3("system_key_data_3");
    Key *key3= new Key("percona_key:0:2", "AES", NULL, key_data3.c_str(), key_data3.length()+1);
    key3->xor_data();

    sys_keys_container.store_or_update_if_system_key(key3);

    Key key_id("percona_key:0", NULL, NULL, NULL,0);

    IKey* system_key = sys_keys_container.get_latest_key_if_system_key(&key_id);

    ASSERT_TRUE(system_key != NULL);

    Key key(system_key->get_key_id()->c_str(), system_key->get_key_type()->c_str(), system_key->get_user_id()->c_str(),
            system_key->get_key_data(), system_key->get_key_data_size());
    key.xor_data();        
    uchar* key_data_fetched= key.get_key_data();
    size_t key_data_fetched_size= key.get_key_data_size();
    std::string key_data_with_version = "2:" + key_data3;
    EXPECT_STREQ(key.get_key_id()->c_str(), "percona_key:0:2");
    EXPECT_STREQ(key_data_with_version.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", key.get_key_type()->c_str());
    ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

    delete key1;
    delete key2;
    delete key3;
  }


  TEST_F(System_keys_container_test, StoreKeyWithTheSameIdTwice)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    key1->xor_data();

    sys_keys_container.store_or_update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:0", "AES", NULL, key_data2.c_str(), key_data2.length()+1);
    key2->xor_data();

    sys_keys_container.store_or_update_if_system_key(key2);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);

    IKey* system_key = sys_keys_container.get_latest_key_if_system_key(&key_id);

    Key key(system_key->get_key_id()->c_str(), system_key->get_key_type()->c_str(), system_key->get_user_id()->c_str(),
            system_key->get_key_data(), system_key->get_key_data_size());
    key.xor_data();        
    uchar* key_data_fetched= key.get_key_data();
    size_t key_data_fetched_size= key.get_key_data_size();
    std::string key_data_with_version = "0:" + key_data1;
    EXPECT_STREQ(key.get_key_id()->c_str(), "percona_binlog:0");
    EXPECT_STREQ(key_data_with_version.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", key.get_key_type()->c_str());
    ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

    delete key1;
    delete key2;
  }

  TEST_F(System_keys_container_test, StoreKeyWithTheSameIdTwiceAndThenWithDifferentOne)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    key1->xor_data();

    sys_keys_container.store_or_update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:0", "AES", NULL, key_data2.c_str(), key_data2.length()+1);
    key2->xor_data();

    sys_keys_container.store_or_update_if_system_key(key2);

    std::string key_data3("system_key_data_3");
    Key *key3= new Key("percona_binlog:1", "AES", NULL, key_data3.c_str(), key_data3.length()+1);
    key3->xor_data();

    sys_keys_container.store_or_update_if_system_key(key3);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);

    IKey* system_key = sys_keys_container.get_latest_key_if_system_key(&key_id);

    Key key(system_key->get_key_id()->c_str(), system_key->get_key_type()->c_str(), system_key->get_user_id()->c_str(),
            system_key->get_key_data(), system_key->get_key_data_size());
    key.xor_data();        
    uchar* key_data_fetched= key.get_key_data();
    size_t key_data_fetched_size= key.get_key_data_size();
    std::string key_data_with_version = "1:" + key_data3;
    EXPECT_STREQ(key.get_key_id()->c_str(), "percona_binlog:1");
    EXPECT_STREQ(key_data_with_version.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", key.get_key_type()->c_str());
    ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

    delete key1;
    delete key2;
    delete key3;
  }

  TEST_F(System_keys_container_test, StoreKey1StoreKey1StoreKey2FetchKey1)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    key1->xor_data();

    sys_keys_container.store_or_update_if_system_key(key1);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:1", "AES", NULL, key_data2.c_str(), key_data2.length()+1);
    key2->xor_data();

    sys_keys_container.store_or_update_if_system_key(key2);

    std::string key_data3("system_key_data_3");
    Key *key3= new Key("percona_key:2", "AES", NULL, key_data3.c_str(), key_data3.length()+1);
    key3->xor_data();

    sys_keys_container.store_or_update_if_system_key(key3);

    Key key_id("percona_binlog", NULL, NULL, NULL,0);

    IKey* system_key = sys_keys_container.get_latest_key_if_system_key(&key_id);

    Key key(system_key->get_key_id()->c_str(), system_key->get_key_type()->c_str(), system_key->get_user_id()->c_str(),
            system_key->get_key_data(), system_key->get_key_data_size());
    key.xor_data();        
    uchar* key_data_fetched= key.get_key_data();
    size_t key_data_fetched_size= key.get_key_data_size();
    std::string key_data_with_version = "1:" + key_data2;
    EXPECT_STREQ(key.get_key_id()->c_str(), "percona_binlog:1");
    EXPECT_STREQ(key_data_with_version.c_str(), reinterpret_cast<const char*>(key_data_fetched));
    EXPECT_STREQ("AES", key.get_key_type()->c_str());
    ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

    delete key1;
    delete key2;
    delete key3;
  }

  TEST_F(System_keys_container_test, IfSystemKey)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    EXPECT_EQ(sys_keys_container.is_system_key(key1), true);

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_key231dqwldk__23_:1", "AES", NULL, key_data2.c_str(), key_data2.length()+1);

    EXPECT_EQ(sys_keys_container.is_system_key(key2), true);

    std::string key_data3("system_key_data_3");
    Key *key3= new Key("percona_binlog:2", "AES", NULL, key_data3.c_str(), key_data3.length()+1);

    EXPECT_EQ(sys_keys_container.is_system_key(key3), true);

    std::string key_data("system_key_data");
    Key *key_without_version= new Key("percona_binlog", "AES", NULL, key_data.c_str(), key_data.length()+1);

    EXPECT_EQ(sys_keys_container.is_system_key(key_without_version), true);

    std::string not_system_key_data("not_system_key_data");
    Key *not_system_key= new Key("unicorn_binlog", "AES", NULL, not_system_key_data.c_str(), not_system_key_data.length()+1);

    EXPECT_EQ(sys_keys_container.is_system_key(not_system_key), false);

    delete key1;
    delete key2;
    delete key3;
    delete key_without_version;
    delete not_system_key;
  }

  TEST_F(System_keys_container_test, GetKeyWithRotattedId)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("percona_binlog:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.store_or_update_if_system_key(key1);

    Key *percona_binlog_key = new Key("percona_binlog", "AES", NULL, "sys_key", 8);
    EXPECT_EQ(sys_keys_container.rotate_key_id_if_existing_system_key(percona_binlog_key), false);
    EXPECT_STREQ(percona_binlog_key->get_key_id()->c_str(), "percona_binlog:1");

    std::string key_data2("system_key_data_2");
    Key *key2= new Key("percona_binlog:1", "AES", NULL, key_data2.c_str(), key_data2.length()+1);

    sys_keys_container.store_or_update_if_system_key(key2);

    Key *percona_binlog_key2 = new Key("percona_binlog", "AES", NULL, "sys_key", 8);
    EXPECT_EQ(sys_keys_container.rotate_key_id_if_existing_system_key(percona_binlog_key2), false);
    EXPECT_STREQ(percona_binlog_key2->get_key_id()->c_str(), "percona_binlog:2");

    std::string key_data3("system_key_data_3");
    Key *key3= new Key("percona_binlog:2", "AES", NULL, key_data3.c_str(), key_data3.length()+1);

    sys_keys_container.store_or_update_if_system_key(key3);

    Key *percona_binlog_key3 = new Key("percona_binlog", "AES", NULL, "sys_key", 8);
    EXPECT_EQ(sys_keys_container.rotate_key_id_if_existing_system_key(percona_binlog_key3), false);
    EXPECT_STREQ(percona_binlog_key3->get_key_id()->c_str(), "percona_binlog:3");

    Key *key1_sk= new Key("percona_key:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.store_or_update_if_system_key(key1_sk);

    Key *percona_key = new Key("percona_key", "AES", NULL, "sys_key", 8);
    EXPECT_EQ(sys_keys_container.rotate_key_id_if_existing_system_key(percona_key), false);
    EXPECT_STREQ(percona_key->get_key_id()->c_str(), "percona_key:1");

    delete key1;
    delete key2;
    delete key3;
    delete key1_sk;
    delete percona_key;
  }

  TEST_F(System_keys_container_test, RotateOnNotSystemKey)
  {
    std::string key_data1("system_key_data_1");
    Key *key1= new Key("not_system_key:0", "AES", NULL, key_data1.c_str(), key_data1.length()+1);

    sys_keys_container.store_or_update_if_system_key(key1);

    Key *key_1_id = new Key("not_system_key:0", "AES", NULL, "sys_key", 8);
    EXPECT_EQ(sys_keys_container.rotate_key_id_if_existing_system_key(key_1_id), false);
    EXPECT_STREQ(key_1_id->get_key_id()->c_str(), "not_system_key:0");

    delete key1;
    delete key_1_id;
  }

  TEST_F(System_keys_container_test, RotateToMaxKeyId)
  {
    std::string key_data1("system_key_data");
    std::ostringstream correct_percona_binlog_key_id_ss;
    correct_percona_binlog_key_id_ss << "percona_binlog:";
    correct_percona_binlog_key_id_ss << (LONG_MAX - 1);
    std::string correct_percona_binlog_key_id = correct_percona_binlog_key_id_ss.str();

    Key *key1= new Key(correct_percona_binlog_key_id.c_str(), "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    sys_keys_container.store_or_update_if_system_key(key1);

    Key *percona_binlog_key = new Key("percona_binlog", "AES", NULL, "sys_key", 8);
    EXPECT_EQ(sys_keys_container.rotate_key_id_if_existing_system_key(percona_binlog_key), false);

    std::ostringstream max_percona_binlog_key_id_ss;
    max_percona_binlog_key_id_ss << "percona_binlog:";
    max_percona_binlog_key_id_ss << LONG_MAX;
    std::string max_percona_binlog_key_id = max_percona_binlog_key_id_ss.str();

    EXPECT_STREQ(percona_binlog_key->get_key_id()->c_str(), max_percona_binlog_key_id.c_str());

    std::ostringstream correct_percona_key_id_ss;
    correct_percona_key_id_ss << "percona_key:";
    correct_percona_key_id_ss << (LONG_MAX - 1);
    std::string correct_percona_key_id = correct_percona_key_id_ss.str();

    Key *key2= new Key(correct_percona_key_id.c_str(), "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    sys_keys_container.store_or_update_if_system_key(key2);

    Key *percona_key = new Key("percona_key", "AES", NULL, "sys_key", 8);
    EXPECT_EQ(sys_keys_container.rotate_key_id_if_existing_system_key(percona_key), false);

    std::ostringstream max_percona_key_id_ss;
    max_percona_key_id_ss << "percona_key:";
    max_percona_key_id_ss << LONG_MAX;
    std::string max_percona_key_id = max_percona_key_id_ss.str();

    EXPECT_STREQ(percona_key->get_key_id()->c_str(), max_percona_key_id.c_str());

    delete key1;
    delete key2;
  }

  TEST_F(System_keys_container_test, RotateFromMaxKeyId)
  {
    std::string key_data1("system_key_data");
    std::ostringstream max_percona_binlog_key_id_ss;
    max_percona_binlog_key_id_ss << "percona_binlog:";
    max_percona_binlog_key_id_ss << LONG_MAX;
    std::string max_percona_binlog_key_id = max_percona_binlog_key_id_ss.str();

    Key *key1= new Key(max_percona_binlog_key_id.c_str(), "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    sys_keys_container.store_or_update_if_system_key(key1);

    Key *percona_binlog_key = new Key("percona_binlog", "AES", NULL, "sys_key", 8);
    EXPECT_EQ(sys_keys_container.rotate_key_id_if_existing_system_key(percona_binlog_key), true);

    EXPECT_STREQ(percona_binlog_key->get_key_id()->c_str(), "percona_binlog");

    std::ostringstream max_percona_key_id_ss;
    max_percona_key_id_ss << "percona_key:";
    max_percona_key_id_ss << LONG_MAX;
    std::string max_percona_key_id = max_percona_key_id_ss.str();

    Key *key2= new Key(max_percona_key_id.c_str(), "AES", NULL, key_data1.c_str(), key_data1.length()+1);
    sys_keys_container.store_or_update_if_system_key(key2);

    Key *percona_key = new Key("percona_key", "AES", NULL, "sys_key", 8);
    EXPECT_EQ(sys_keys_container.rotate_key_id_if_existing_system_key(percona_key), true);

    EXPECT_STREQ(percona_key->get_key_id()->c_str(), "percona_key");

    delete key1;
  }

  TEST_F(System_keys_container_test, FetchFromEmptyContainer)
  {
    Key key_id("percona_binlog", NULL, NULL, NULL,0);

    IKey* system_key = sys_keys_container.get_latest_key_if_system_key(&key_id);

    ASSERT_TRUE(system_key == NULL);
  }
} //namespace keyring__system_keys_container_unittest
