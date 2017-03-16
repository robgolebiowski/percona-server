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

  using ::testing::Return;
  using ::testing::StrEq;
  using ::testing::_;
  using ::testing::SetArgPointee;

  class Vault_io_test : public ::testing::Test
  {
  protected:
    virtual void SetUp()
    {
//      keyring_file_data_key = PSI_NOT_INSTRUMENTED;
//      keyring_backup_file_data_key = PSI_NOT_INSTRUMENTED;
      correct_token = "8d774695-81b8-8307-83e4-2877476cffbb"; //maybe this could be passed as a parameter to unit test ?
      credential_file_url = "./credentials";
      credential_file_was_created = false;
      logger= new Mock_logger();
      vault_curl = new Vault_curl(logger);
    }

    virtual void TearDown()
    {
      if (credential_file_was_created)
        std::remove(credential_file_url.c_str());
//      fake_mysql_plugin.name.str= const_cast<char*>("FakeKeyringPlugin");
//      fake_mysql_plugin.name.length= strlen("FakeKeyringPlugin");
      delete logger;
      //delete vault_curl;
    }

  protected:
    void create_credentials_file_with_correct_token();

//    st_plugin_int fake_mysql_plugin;
    ILogger *logger;
    IVault_curl *vault_curl;
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

  TEST_F(Vault_io_test, InitWithNotExisitingCredentialFile)
  {
    std::string credential_file_name("./some_funny_name");
    Vault_io vault_io(logger, vault_curl);
    remove(credential_file_name.c_str());
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not open file with credentials.")));
    EXPECT_EQ(vault_io.init(&credential_file_name), TRUE);

    remove(credential_file_name.c_str());
  }

  TEST_F(Vault_io_test, InitWithInvalidToken)
  {
    Vault_io vault_io(logger, vault_curl);

    std::string token_in_file("What-a-pretty-token");

    std::remove(credential_file_url.c_str());
    std::ofstream myfile;
    myfile.open(credential_file_url.c_str());
    myfile << token_in_file;
    myfile.close();
    //***

    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not retrieve list of keys from Vault. "
          "Vault has returned the following error(s): [\"permission denied\"]")));
    ISerialized_object *serialized_keys= NULL;
    EXPECT_EQ(vault_io.get_serialized_object(&serialized_keys), TRUE);

    std::remove(credential_file_url.c_str());
  }

  TEST_F(Vault_io_test, GetSerializedObjectWithTwoKeys)
  {
    Vault_io vault_io(logger, vault_curl);
    create_credentials_file_with_correct_token();

    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    //First Add Two keys into Vault
    Vault_key key1("key1", "AES", "Arczi", "Artur", 5);
    EXPECT_STREQ(key1.get_key_signature()->c_str(), "4_key15_Arczi");
    key1.set_key_operation(STORE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key1), FALSE);
    Vault_key key2("key2", "AES", "Kamil", "Kami", 4);
    EXPECT_STREQ(key2.get_key_signature()->c_str(), "4_key25_Kamil");
    key2.set_key_operation(STORE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key2), FALSE);
    //*****

    //Now fetch two keys with separate Vault_io
    ISerialized_object *serialized_keys= NULL;
    EXPECT_EQ(vault_io.get_serialized_object(&serialized_keys), FALSE);
    IKey *key1_loaded= NULL;
    ASSERT_TRUE(serialized_keys != NULL);
    EXPECT_EQ(serialized_keys->has_next_key(), TRUE);
    serialized_keys->get_next_key(&key1_loaded);
    EXPECT_STREQ(key1_loaded->get_key_signature()->c_str(), "4_key15_Arczi");
    IKey *key2_loaded= NULL;
    delete key1_loaded;
    EXPECT_EQ(serialized_keys->has_next_key(), TRUE);
    serialized_keys->get_next_key(&key2_loaded);
    EXPECT_STREQ(key2_loaded->get_key_signature()->c_str(), "4_key25_Kamil");
    delete key2_loaded;
    EXPECT_EQ(serialized_keys->has_next_key(), FALSE);
    delete serialized_keys;

    //Now remove the keys
    Vault_key key1_to_remove(key1);
    key1_to_remove.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key1_to_remove), FALSE);
    Vault_key key2_to_remove(key2);
    key2_to_remove.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key2_to_remove), FALSE);
  }

  TEST_F(Vault_io_test, GetSerializedObjectWithTwoKeysWithDifferentVaultIO)
  {
    Vault_io vault_io_for_storing(logger, vault_curl);
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
    Vault_curl *vault_curl2 = new Vault_curl(logger);
    Vault_io vault_io_for_fetching(logger, vault_curl2);
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
    Vault_key key1_to_remove(key1);
    key1_to_remove.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io_for_storing.flush_to_storage(&key1_to_remove), FALSE);
    Vault_key key2_to_remove(key2);
    key2_to_remove.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io_for_storing.flush_to_storage(&key2_to_remove), FALSE);
  }

  TEST_F(Vault_io_test, RetrieveKeyTypeAndValue)
  {
    Vault_io vault_io(logger, vault_curl);
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

    Vault_key key_to_remove("key1", NULL, "rob", NULL, 0);
    key_to_remove.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key_to_remove), FALSE);
  }

  TEST_F(Vault_io_test, FlushAndRemoveSingleKey)
  {
    Vault_io vault_io(logger, vault_curl);
    create_credentials_file_with_correct_token();
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);
    Vault_key key("key1", "AES", "rob", "Robi", 4);
    key.set_key_operation(STORE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key), FALSE);
    Vault_key key_to_remove(key);
    key_to_remove.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key_to_remove), FALSE);
  }

  TEST_F(Vault_io_test, FlushKeyRetrieveDeleteInit)
  {
    Vault_io vault_io(logger, vault_curl);
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

    Vault_key key_to_remove(key);
    key_to_remove.set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_io.flush_to_storage(&key_to_remove), FALSE);

    Vault_curl *vault_curl2 = new Vault_curl(logger);
    Vault_io vault_io2(logger, vault_curl2); //do I need this ?
    EXPECT_EQ(vault_io2.init(&credential_file_url), FALSE);
    ISerialized_object *serialized_keys= NULL;
    EXPECT_EQ(vault_io2.get_serialized_object(&serialized_keys), FALSE);
    ASSERT_TRUE(serialized_keys == NULL); //no keys
  }

  class Mock_vault_curl : public IVault_curl
  {
  public:
    MOCK_METHOD2(init, my_bool(std::string *vault_url, std::string *auth_token));
    MOCK_METHOD1(list_keys, my_bool(std::string *response));
    MOCK_METHOD2(write_key, my_bool(IKey *key, std::string *response));
    MOCK_METHOD2(read_key, my_bool(IKey *key, std::string *response));
    MOCK_METHOD2(delete_key, my_bool(IKey *key, std::string *response));
  };

  TEST_F(Vault_io_test, ErrorFromVaultCurlOnVaultIOInit)
  {
    Mock_vault_curl *mock_curl = new Mock_vault_curl();
    Vault_io vault_io(logger, mock_curl);
    create_credentials_file_with_correct_token();

    std::string url = "http://127.0.0.1:8200";

    EXPECT_CALL(*mock_curl, init(Pointee(StrEq(url)), Pointee(StrEq(correct_token))))
      .WillOnce(Return(TRUE)); // init unsuccessfull
    EXPECT_EQ(vault_io.init(&credential_file_url), TRUE);
  }

  TEST_F(Vault_io_test, ErrorFromVaultCurlOnListKeys)
  {
    Mock_vault_curl *mock_curl = new Mock_vault_curl();
    Vault_io vault_io(logger, mock_curl);
    create_credentials_file_with_correct_token();

    std::string url = "http://127.0.0.1:8200";

    EXPECT_CALL(*mock_curl, init(Pointee(StrEq(url)), Pointee(StrEq(correct_token))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    ISerialized_object *serialized_object;

    EXPECT_CALL(*mock_curl, list_keys(_))
      .WillOnce(Return(TRUE)); //failed to list keys
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not retrieve list of keys from Vault.")));

    EXPECT_EQ(vault_io.get_serialized_object(&serialized_object), TRUE);
    EXPECT_EQ(serialized_object, reinterpret_cast<ISerialized_object*>(NULL));
  }

  TEST_F(Vault_io_test, ErrorsFromVaultInVaultsResponseOnListKeys)
  {
    Mock_vault_curl *mock_curl = new Mock_vault_curl();
    Vault_io vault_io(logger, mock_curl);
    create_credentials_file_with_correct_token();

    std::string url = "http://127.0.0.1:8200";

    EXPECT_CALL(*mock_curl, init(Pointee(StrEq(url)), Pointee(StrEq(correct_token))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    ISerialized_object *serialized_object;
    std::string vault_response("{ errors: [\"list is broken\"] }"); 

    EXPECT_CALL(*mock_curl, list_keys(_))
      .WillOnce(DoAll(SetArgPointee<0>(vault_response), Return(FALSE)));
      
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not retrieve list of keys from Vault. Vault has returned the following error(s): [\"list is broken\"]")));

    EXPECT_EQ(vault_io.get_serialized_object(&serialized_object), TRUE);
    EXPECT_EQ(serialized_object, reinterpret_cast<ISerialized_object*>(NULL));

    vault_response = "{errors: [\"list is broken\", \"and some other error\"]}"; 

    EXPECT_CALL(*mock_curl, list_keys(_))
      .WillOnce(DoAll(SetArgPointee<0>(vault_response), Return(FALSE)));
      
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not retrieve list of keys from Vault. Vault has returned the following error(s): [\"list is broken\", \"and some other error\"]")));

    EXPECT_EQ(vault_io.get_serialized_object(&serialized_object), TRUE);
    EXPECT_EQ(serialized_object, reinterpret_cast<ISerialized_object*>(NULL));

    vault_response = "{ errors: [\"list is broken\",\n\"and some other error\"\n] }"; 

    EXPECT_CALL(*mock_curl, list_keys(_))
      .WillOnce(DoAll(SetArgPointee<0>(vault_response), Return(FALSE)));
      
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not retrieve list of keys from Vault. Vault has returned the following error(s): [\"list is broken\",\"and some other error\"]")));

    EXPECT_EQ(vault_io.get_serialized_object(&serialized_object), TRUE);
    EXPECT_EQ(serialized_object, reinterpret_cast<ISerialized_object*>(NULL));
 
    //delete mock_curl;
  }

  TEST_F(Vault_io_test, ErrorsFromVaultCurlOnReadKey)
  {
    Mock_vault_curl *mock_curl = new Mock_vault_curl();
    Vault_io vault_io(logger, mock_curl);
    create_credentials_file_with_correct_token();

    std::string url = "http://127.0.0.1:8200";

    EXPECT_CALL(*mock_curl, init(Pointee(StrEq(url)), Pointee(StrEq(correct_token))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    IKey *key = NULL;

    EXPECT_CALL(*mock_curl, read_key(key, _))
      .WillOnce(Return(TRUE));
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not read key from Vault")));
    EXPECT_EQ(vault_io.retrieve_key_type_and_value(key), TRUE);

    //delete mock_curl;
  }

  TEST_F(Vault_io_test, ErrorsFromVaultInVaultsCurlResponseOnReadKey)
  {
    Mock_vault_curl *mock_curl = new Mock_vault_curl();
    Vault_io vault_io(logger, mock_curl);
    create_credentials_file_with_correct_token();

    std::string url = "http://127.0.0.1:8200";

    EXPECT_CALL(*mock_curl, init(Pointee(StrEq(url)), Pointee(StrEq(correct_token))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    IKey *key = NULL;
    std::string vault_response("{ errors: [\"Cannot read this stuff\"] }"); 

    EXPECT_CALL(*mock_curl, read_key(key, _))
      .WillOnce(DoAll(SetArgPointee<1>(vault_response), Return(FALSE)));
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not read key from Vault Vault has returned the following error(s):"
                                " [\"Cannot read this stuff\"]")));
    EXPECT_EQ(vault_io.retrieve_key_type_and_value(key), TRUE);

    //delete mock_curl;
  }

  TEST_F(Vault_io_test, ErrorsFromVaultCurlOnDeleteKey)
  {
    Mock_vault_curl *mock_curl = new Mock_vault_curl();
    Vault_io vault_io(logger, mock_curl);
    create_credentials_file_with_correct_token();

    std::string url = "http://127.0.0.1:8200";

    EXPECT_CALL(*mock_curl, init(Pointee(StrEq(url)), Pointee(StrEq(correct_token))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    Vault_key key("key1", "AES", "Arczi", "Artur", 5);
    key.set_key_operation(REMOVE_KEY);

    EXPECT_CALL(*mock_curl, delete_key(_,_))
      .WillOnce(Return(TRUE));
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not delete key from Vault")));
    EXPECT_EQ(vault_io.flush_to_storage(&key), TRUE);

    //delete mock_curl;
  }

  TEST_F(Vault_io_test, ErrorsFromVaultInVaultsCurlResponseOnDeleteKey)
  {
    Mock_vault_curl *mock_curl = new Mock_vault_curl();
    Vault_io vault_io(logger, mock_curl);
    create_credentials_file_with_correct_token();

    std::string url = "http://127.0.0.1:8200";

    EXPECT_CALL(*mock_curl, init(Pointee(StrEq(url)), Pointee(StrEq(correct_token))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    Vault_key key("key1", "AES", "Arczi", "Artur", 5);
    key.set_key_operation(REMOVE_KEY);
    std::string vault_response("{ errors: [\"Cannot delete this stuff\"] }"); 

    EXPECT_CALL(*mock_curl, delete_key(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(vault_response), Return(FALSE)));
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not delete key from Vault Vault has returned the following error(s):"
                                " [\"Cannot delete this stuff\"]")));
    EXPECT_EQ(vault_io.flush_to_storage(&key), TRUE);
  }

  TEST_F(Vault_io_test, ErrorsFromVaultCurlOnWriteKey)
  {
    Mock_vault_curl *mock_curl = new Mock_vault_curl();
    Vault_io vault_io(logger, mock_curl);
    create_credentials_file_with_correct_token();

    std::string url = "http://127.0.0.1:8200";

    EXPECT_CALL(*mock_curl, init(Pointee(StrEq(url)), Pointee(StrEq(correct_token))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    Vault_key key("key1", "AES", "Arczi", "Artur", 5);
    key.set_key_operation(STORE_KEY);

    EXPECT_CALL(*mock_curl, write_key(_,_))
      .WillOnce(Return(TRUE));
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not write key to Vault")));
    EXPECT_EQ(vault_io.flush_to_storage(&key), TRUE);
  }

  TEST_F(Vault_io_test, ErrorsFromVaultInVaultsCurlResponseOnWriteKey)
  {
    Mock_vault_curl *mock_curl = new Mock_vault_curl();
    Vault_io vault_io(logger, mock_curl);
    create_credentials_file_with_correct_token();

    std::string url = "http://127.0.0.1:8200";

    EXPECT_CALL(*mock_curl, init(Pointee(StrEq(url)), Pointee(StrEq(correct_token))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_EQ(vault_io.init(&credential_file_url), FALSE);

    Vault_key key("key1", "AES", "Arczi", "Artur", 5);
    key.set_key_operation(STORE_KEY);
    std::string vault_response("{ errors: [\"Cannot write this stuff\"] }"); 

    EXPECT_CALL(*mock_curl, write_key(_, _))
      .WillOnce(DoAll(SetArgPointee<1>(vault_response), Return(FALSE)));
    //TODO: Add dot after Vault (before 2nd Vault)
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not write key to Vault Vault has returned the following error(s):"
                                " [\"Cannot write this stuff\"]")));
    EXPECT_EQ(vault_io.flush_to_storage(&key), TRUE);
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
