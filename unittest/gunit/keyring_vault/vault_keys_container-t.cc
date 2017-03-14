#include <my_global.h>
#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <mysql/plugin_keyring.h>
#include "vault_keys_container.h"
#include "mock_logger.h"
#include <fstream>
#include "i_serialized_object.h"

#if !defined(MERGE_UNITTESTS) //TODO: Look into merging
#ifdef HAVE_PSI_INTERFACE
namespace keyring
{
  PSI_memory_key key_memory_KEYRING = PSI_NOT_INSTRUMENTED;
  PSI_memory_key key_LOCK_keyring = PSI_NOT_INSTRUMENTED;
}
#endif
mysql_rwlock_t LOCK_keyring;
#endif

namespace keyring__vault_keys_container_unittest
{
  using namespace keyring;
  using ::testing::Return;
  using ::testing::InSequence;
  using ::testing::_;
  using ::testing::StrEq;
  using ::testing::DoAll;
  using ::testing::SetArgPointee;
  using ::testing::WithArgs;
  using ::testing::Invoke;

  class Vault_keys_container_test : public ::testing::Test
  {
  public:
    Vault_keys_container_test() : file_name("./keyring") {}
  protected:
    virtual void SetUp()
    {
      sample_key_data= "Robi";
      sample_key= new Vault_key("Roberts_key", "AES", "Robert", sample_key_data.c_str(), sample_key_data.length());

//      remove(file_name.c_str());
//      remove("./keyring.backup");

      correct_token = "a974abd1-ac3f-f7c9-4b81-2629500ad99f"; //maybe this could be passed as a parameter to unit test ?
      credential_file_url = "./credentials";
      credential_file_was_created = false;
      logger= new Mock_logger();
      vault_keys_container= new Vault_keys_container(logger);
      vault_curl = new Vault_curl(logger);
    }
    virtual void TearDown()
    {
      if(credential_file_was_created)
        remove(credential_file_url.c_str());
      delete vault_keys_container;
      delete logger;
      delete vault_curl;
    }

    void create_credentials_file_with_correct_token();

//    void create_keyring_file(const char *file_name, const char *keyring_buffer);
//    void generate_keyring_file_with_correct_structure(const char *file_name);
//    void generate_keyring_file_with_incorrect_file_version(const char *file_name);
//    void generate_keyring_file_with_incorrect_TAG(const char *file_name);
  protected:
    Vault_keys_container *vault_keys_container;
    ILogger *logger;
    IVault_curl *vault_curl;
    std::string correct_token;
    std::string credential_file_url;
    bool credential_file_was_created;
    Vault_key *sample_key;
    std::string sample_key_data;
    std::string file_name;
  };

  void Vault_keys_container_test::create_credentials_file_with_correct_token()
  {
    std::remove(credential_file_url.c_str());
    std::ofstream myfile;
    myfile.open(credential_file_url.c_str());
    myfile << correct_token;
    myfile.close();
    credential_file_was_created = true;
  }

/*  void Keys_container_test::create_keyring_file(const char *file_name, const char *keyring_buffer)
  {
    std::fstream file;
    file.open(file_name,
              std::fstream::out | std::fstream::binary | std::fstream::trunc);
    ASSERT_TRUE(file.is_open());
    file.write(keyring_buffer, strlen(keyring_buffer));
    file.close();
  }

  void Keys_container_test::generate_keyring_file_with_correct_structure(const char *file_name)
  {
    static const char *keyring_buffer= "Keyring file version:1.0EOF";
    create_keyring_file(file_name, keyring_buffer);
  }

  void Keys_container_test::generate_keyring_file_with_incorrect_file_version(const char *file_name)
  {
    static const char *keyring_buffer= "Keyring file version:2.0EOF";
    create_keyring_file(file_name, keyring_buffer);
  }

  void Keys_container_test::generate_keyring_file_with_incorrect_TAG(const char *file_name)
  {
    static const char *keyring_buffer= "Keyring file version:2.0EF";
    create_keyring_file(file_name, keyring_buffer);
  }*/

  TEST_F(Vault_keys_container_test, InitWithCorrectCredential)
  {
    create_credentials_file_with_correct_token();
    IKeyring_io *vault_io= new Vault_io(logger, vault_curl);
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), FALSE);
    delete sample_key; //unused in this test
  }

  TEST_F(Vault_keys_container_test, InitWithFileWithInvalidToken)
  {
    std::string token_in_file("What-a-pretty-token");

    std::remove(credential_file_url.c_str());
    std::ofstream myfile;
    myfile.open(credential_file_url.c_str());
    myfile << token_in_file;
    myfile.close();

    IKeyring_io *vault_io= new Vault_io(logger, vault_curl);

    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not retrieve list of keys from Vault. "
                                "Vault has returned the following error(s): [\"permission denied\"]")));
    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Error while loading keyring content. The keyring might be malformed")));
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), TRUE);
    delete sample_key; //unused in this test

    std::remove(credential_file_url.c_str());
  }

  TEST_F(Vault_keys_container_test, InitWithEmptyCredentialFile)
  {
    std::remove(credential_file_url.c_str());
    std::ofstream myfile;
    myfile.open(credential_file_url.c_str());
    myfile.close();

    IKeyring_io *vault_io= new Vault_io(logger, vault_curl);

    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not read token from credential file.")));
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), TRUE);
    delete sample_key; //unused in this test

    std::remove(credential_file_url.c_str());
  }

/*
  TEST_F(Keys_container_test, InitWithFileWithIncorrectTAG)
  {
    const char *keyring_incorrect_tag= "./keyring_incorrect_tag";
    remove(keyring_incorrect_tag);
    generate_keyring_file_with_incorrect_TAG(keyring_incorrect_tag);
    IKeyring_io *keyring_io= new Buffered_file_io(logger);
    EXPECT_CALL(*((Mock_logger *)logger),
                log(MY_ERROR_LEVEL, StrEq("Error while loading keyring content. The keyring might be malformed")));
    EXPECT_EQ(keys_container->init(keyring_io, keyring_incorrect_tag), 1);
    remove(keyring_incorrect_tag);
    delete sample_key; //unused in this test
  }
*/
  TEST_F(Vault_keys_container_test, StoreFetchRemove)
  {
    create_credentials_file_with_correct_token();

    IKeyring_io *vault_io= new Vault_io(logger, vault_curl);
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), FALSE);
    EXPECT_EQ(vault_keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    Vault_key key_id("Roberts_key", NULL, "Robert",NULL,0);
    IKey* fetched_key= vault_keys_container->fetch_key(&key_id);

    ASSERT_TRUE(fetched_key != NULL);
    std::string expected_key_signature= "11_Roberts_key6_Robert";
    EXPECT_STREQ(fetched_key->get_key_signature()->c_str(), expected_key_signature.c_str());
    EXPECT_EQ(fetched_key->get_key_signature()->length(), expected_key_signature.length());
    uchar* key_data_fetched= fetched_key->get_key_data();
    size_t key_data_fetched_size= fetched_key->get_key_data_size();
    EXPECT_EQ(memcmp(sample_key_data.c_str(), reinterpret_cast<const char*>(key_data_fetched),
                     key_data_fetched_size), 0);
    EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
    ASSERT_TRUE(sample_key_data.length() == key_data_fetched_size);

    vault_keys_container->remove_key(&key_id);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);
    my_free(fetched_key->release_key_data());
  }

  TEST_F(Vault_keys_container_test, FetchNotExisting)
  {
    create_credentials_file_with_correct_token();

    IKeyring_io *keyring_io= new Vault_io(logger, vault_curl);
    EXPECT_EQ(vault_keys_container->init(keyring_io, credential_file_url), 0);
    Key key_id("Roberts_key", NULL, "Robert",NULL,0);
    IKey* fetched_key= vault_keys_container->fetch_key(&key_id);
    ASSERT_TRUE(fetched_key == NULL);
    delete sample_key; //unused in this test
  }

  TEST_F(Vault_keys_container_test, RemoveNotExisting)
  {
    create_credentials_file_with_correct_token();

    IKeyring_io *keyring_io= new Vault_io(logger, vault_curl);
    EXPECT_EQ(vault_keys_container->init(keyring_io, credential_file_url), 0);
    Key key_id("Roberts_key", "AES", "Robert",NULL,0);
    ASSERT_TRUE(vault_keys_container->remove_key(&key_id) == TRUE);
    delete sample_key; //unused in this test
  }

  TEST_F(Vault_keys_container_test, StoreFetchNotExistingDelete)
  {
    create_credentials_file_with_correct_token();

    IKeyring_io *keyring_io= new Vault_io(logger, vault_curl);
    EXPECT_EQ(vault_keys_container->init(keyring_io, credential_file_url), 0);
    EXPECT_EQ(vault_keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);
    Key key_id("NotRoberts_key", NULL, "NotRobert",NULL,0);
    IKey* fetched_key= vault_keys_container->fetch_key(&key_id);
    ASSERT_TRUE(fetched_key == NULL);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    EXPECT_EQ(vault_keys_container->remove_key(sample_key), FALSE);
    EXPECT_EQ(vault_keys_container->get_number_of_keys(), (ulong)0);
  }

  TEST_F(Vault_keys_container_test, StoreRemoveNotExisting)
  {
    create_credentials_file_with_correct_token();

    IKeyring_io *keyring_io= new Vault_io(logger, vault_curl);
    EXPECT_EQ(vault_keys_container->init(keyring_io, credential_file_url), 0);
    EXPECT_EQ(vault_keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);
    Key key_id("NotRoberts_key", "AES", "NotRobert",NULL,0);
    // Failed to remove key
    ASSERT_TRUE(vault_keys_container->remove_key(&key_id) == TRUE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    //Clean up
    EXPECT_EQ(vault_keys_container->remove_key(sample_key), FALSE);
    EXPECT_EQ(vault_keys_container->get_number_of_keys(), (ulong)0);
  }

  TEST_F(Vault_keys_container_test, StoreStoreStoreFetchRemove)
  {
    create_credentials_file_with_correct_token();

    IKeyring_io *keyring_io= new Vault_io(logger, vault_curl);
    EXPECT_EQ(vault_keys_container->init(keyring_io, credential_file_url), 0);
    EXPECT_EQ(vault_keys_container->store_key(sample_key), FALSE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    std::string key_data1("Robi1");
    Vault_key *key1= new Vault_key("Roberts_key1", "AES", "Robert", key_data1.c_str(), key_data1.length());

    EXPECT_EQ(vault_keys_container->store_key(key1), FALSE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 2);

    std::string key_data2("Robi2");
    Vault_key *key2= new Vault_key("Roberts_key2", "AES", "Robert", key_data2.c_str(), key_data2.length());
    EXPECT_EQ(vault_keys_container->store_key(key2), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 3);

    std::string key_data3("Robi3");
    Vault_key *key3= new Vault_key("Roberts_key3", "AES", "Robert", key_data3.c_str(), key_data3.length());

    EXPECT_EQ(vault_keys_container->store_key(key3), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 4);

    Vault_key key2_id("Roberts_key2", NULL, "Robert",NULL,0);
    IKey* fetched_key= vault_keys_container->fetch_key(&key2_id);

    ASSERT_TRUE(fetched_key != NULL);
    std::string expected_key_signature= "12_Roberts_key26_Robert";
    EXPECT_STREQ(fetched_key->get_key_signature()->c_str(), expected_key_signature.c_str());
    EXPECT_EQ(fetched_key->get_key_signature()->length(), expected_key_signature.length());
    uchar *key_data_fetched= fetched_key->get_key_data();
    size_t key_data_fetched_size= fetched_key->get_key_data_size();
    EXPECT_EQ(memcmp(key_data_fetched, key_data2.c_str(), key_data_fetched_size), 0); 
    ASSERT_TRUE(key_data2.length() == key_data_fetched_size);

    Vault_key key3_id("Roberts_key3", NULL, "Robert",NULL,0);
    vault_keys_container->remove_key(&key3_id);
    vault_keys_container->remove_key(key2);
    vault_keys_container->remove_key(key1);
    vault_keys_container->remove_key(sample_key);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);

    my_free(fetched_key->release_key_data());
  }

  TEST_F(Vault_keys_container_test, StoreTwiceTheSame)
  {
    create_credentials_file_with_correct_token();

    IKeyring_io *keyring_io= new Vault_io(logger, vault_curl);
    EXPECT_EQ(vault_keys_container->init(keyring_io, credential_file_url), 0);
    EXPECT_EQ(vault_keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);
    EXPECT_EQ(vault_keys_container->store_key(sample_key), 1);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    vault_keys_container->remove_key(sample_key);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);
  }
/*
  class Buffered_file_io_dont_remove_backup : public Buffered_file_io
  {
  public:
    Buffered_file_io_dont_remove_backup(ILogger *logger)
      : Buffered_file_io(logger) {}

    my_bool remove_backup(myf myFlags)
    {
      return FALSE;
    }
  };

  class Keys_container_test_dont_close : public ::testing::Test
  {
  public:
    Keys_container_test_dont_close() : file_name("./keyring") {}
  protected:
    virtual void SetUp()
    {
      sample_key_data= "Robi";
      sample_key= new Key("Roberts_key", "AES", "Robert", sample_key_data.c_str(), sample_key_data.length()+1);
      std::string sample_key_data2="xobi2";
      sample_key2= new Key("Roberts_key2", "AES", "Robert", sample_key_data2.c_str(), sample_key_data2.length()+1);

      //Remove Keyring files just to be save
      remove(file_name.c_str());
      remove("./keyring.backup");
      remove("./keyring.backup.backup");
    }
    virtual void TearDown()
    {
      remove(file_name.c_str());
    }
    void generate_malformed_keyring_file_without_tag(const char *file_name);
  protected:
    Key *sample_key;
    Key *sample_key2;
    std::string sample_key_data;
    std::string file_name;
  };

  void Keys_container_test_dont_close::generate_malformed_keyring_file_without_tag(const char *file_name)
  {
    static const char *malformed_keyring_buffer= "Key1AESRobertKEYDATA"
      "Key2AESZibiDATAKey3DATA...crashing";

    std::fstream file;
    file.open(file_name, std::fstream::out | std::fstream::binary | std::fstream::trunc);
    ASSERT_TRUE(file.is_open());
    file.write(malformed_keyring_buffer, strlen(malformed_keyring_buffer));
    file.close();
  }

  TEST_F(Keys_container_test_dont_close, CheckIfCorrectBackupFileIsCreatedAfterStoringOneKey)
  {
    ILogger *logger= new Mock_logger();
    IKeyring_io *keyring_io_dont_remove_backup= new Buffered_file_io_dont_remove_backup(logger);
    Keys_container *keys_container= new Keys_container(logger);

    EXPECT_EQ(keys_container->init(keyring_io_dont_remove_backup, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), TRUE);

    //Check if backup file is empty
    delete keys_container;
    delete logger;
    logger= new Mock_logger();
    IKeyring_io *keyring_io= new Buffered_file_io(logger);
    keys_container= new Keys_container(logger);
    ASSERT_TRUE(keys_container->init(keyring_io, "./keyring.backup") == 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 0);

    remove("./keyring.backup");
    remove("./keyring.backup.backup"); //leftover from initializing keyring with backup file
    remove(file_name.c_str());
    delete keys_container;
    delete logger;
    delete sample_key2; //unused in this test
  }

  TEST_F(Keys_container_test_dont_close, CheckIfCorrectBackupFileIsCreatedAfterStoringTwoKeys)
  {
    ILogger *logger= new Mock_logger();
    IKeyring_io *keyring_io= new Buffered_file_io(logger);
    Keys_container *keys_container= new Keys_container(logger);
    EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
    //successfully stored the key - backup file does not exist
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);
    delete keys_container;
    delete logger;

    logger= new Mock_logger();
    IKeyring_io *keyring_io_dont_remove_backup= new Buffered_file_io_dont_remove_backup(logger);
    keys_container= new Keys_container(logger);

    EXPECT_EQ(keys_container->init(keyring_io_dont_remove_backup, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key2), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), TRUE);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), TRUE);

    delete keys_container;
    delete logger;
    //Check that backup file contains sample_key only
    logger= new Mock_logger();
    IKeyring_io *keyring_io_2= new Buffered_file_io(logger);
    keys_container= new Keys_container(logger);
    EXPECT_EQ(keys_container->init(keyring_io_2, file_name), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
    Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
    IKey *fetchedKey= keys_container->fetch_key(&sample_key_id);
    ASSERT_TRUE(fetchedKey != NULL);

    ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_keyRobert");
    ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "Robi", fetchedKey->get_key_data_size()) == 0);

    remove("./keyring.backup");
    remove("./keyring.backup.backup"); //leftover from initializing keyring with backup file
    remove(file_name.c_str());
    delete keys_container;
    delete logger;
    my_free(fetchedKey->release_key_data());
  }

  TEST_F(Keys_container_test_dont_close, CheckIfCorrectBackupFileIsCreatedBeforeRemovingKey)
  {
    ILogger *logger= new Mock_logger();
    IKeyring_io *keyring_io= new Buffered_file_io(logger);
    Keys_container *keys_container= new Keys_container(logger);

    EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
    //successfully stored the key - backup file does not exist
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);
    EXPECT_EQ(keys_container->store_key(sample_key2), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);

    delete keys_container;
    delete logger;
    logger= new Mock_logger();
    IKeyring_io *keyring_io_dont_remove_backup= new Buffered_file_io_dont_remove_backup(logger);
    keys_container= new Keys_container(logger);

    ASSERT_TRUE(keys_container->init(keyring_io_dont_remove_backup, file_name) == 0);
    Key sample_key_id("Roberts_key", "AES", "Robert", NULL, 0);
    EXPECT_EQ(keys_container->remove_key(&sample_key_id), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), TRUE);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), TRUE);

    delete keys_container;
    delete logger;
    //Check that backup file contains sample_key and sample_key2
    logger= new Mock_logger();
    IKeyring_io *keyring_io_2= new Buffered_file_io(logger);
    keys_container= new Keys_container(logger);
    EXPECT_EQ(keys_container->init(keyring_io_2, "./keyring.backup"), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
    Key sample_key2_id("Roberts_key2", NULL, "Robert", NULL, 0);
    IKey *fetchedKey= keys_container->fetch_key(&sample_key2_id);
    ASSERT_TRUE(fetchedKey != NULL);
    ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_key2Robert");
    ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "xobi2", fetchedKey->get_key_data_size()) == 0);

    remove("./keyring.backup");
    remove("./keyring.backup.backup"); //leftover from initializing keyring with backup file
    remove(file_name.c_str());
    delete keys_container;
    delete logger;
    my_free(fetchedKey->release_key_data());
  }

  TEST_F(Keys_container_test_dont_close, CheckIfBackupFileIsNotCreatedForFetching)
  {
    ILogger *logger= new Mock_logger();
    IKeyring_io *keyring_io= new Buffered_file_io(logger);
    Keys_container *keys_container= new Keys_container(logger);

    EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
    //successfully stored the key - backup file does not exist
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);
    EXPECT_EQ(keys_container->store_key(sample_key2), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);

    delete keys_container;
    delete logger;
    logger= new Mock_logger();
    IKeyring_io *keyring_io_dont_remove_backup= new Buffered_file_io_dont_remove_backup(logger);
    keys_container= new Keys_container(logger);

    EXPECT_EQ(keys_container->init(keyring_io_dont_remove_backup, file_name), 0);
    Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
    IKey *fetchedKey= keys_container->fetch_key(&sample_key_id);
    ASSERT_TRUE(fetchedKey != NULL);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
    //check if the backup file was not created
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), TRUE);

    remove("./keyring.backup");
    remove(file_name.c_str());
    delete keys_container;
    delete logger;
    my_free(fetchedKey->release_key_data());
  }

  TEST_F(Keys_container_test_dont_close, KeyringfileIsMalformedCheckIfBackupIsLoaded)
  {
    ILogger *logger= new Mock_logger();
    IKeyring_io *keyring_io= new Buffered_file_io(logger);
    Keys_container *keys_container= new Keys_container(logger);

    EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
    //successfully stored the key - backup file does not exist
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);
    EXPECT_EQ(keys_container->store_key(sample_key2), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
    //Now we have correct backup file
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);

    delete keys_container;
    delete logger;
    logger= new Mock_logger();
    IKeyring_io *keyring_io_dont_remove_backup= new Buffered_file_io_dont_remove_backup(logger);
    keys_container= new Keys_container(logger);

    //this key will not be in backup file thus we do not care about it
    Key *sample_key3= new Key("Roberts_key3", "ZZZZ", "MaybeRobert", (void*)("DATA"), strlen("DATA"));

    EXPECT_EQ(keys_container->init(keyring_io_dont_remove_backup, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key3), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 3);
    //Now we have correct backup file
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), TRUE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);

    delete keys_container;
    delete logger;
    remove("./keyring");
    generate_malformed_keyring_file_without_tag("./keyring");
    logger= new Mock_logger();
    IKeyring_io *keyring_io_2= new Buffered_file_io(logger);
    keys_container= new Keys_container(logger);

    ASSERT_TRUE(keys_container->init(keyring_io_2, file_name) == 0);
    //Check that keyring from backup was loaded as the keyring file is corrupted
    ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
    Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
    Key sample_key2_id("Roberts_key2", NULL, "Robert", NULL, 0);
    IKey *fetchedKey= keys_container->fetch_key(&sample_key2_id);
    ASSERT_TRUE(fetchedKey != NULL);
    ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_key2Robert");
    ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "xobi2", fetchedKey->get_key_data_size()) == 0);
    IKey *fetchedKey2= keys_container->fetch_key(&sample_key_id);
    ASSERT_TRUE(fetchedKey2 != NULL);
    ASSERT_TRUE(*fetchedKey2->get_key_signature() == "Roberts_keyRobert");
    ASSERT_TRUE(memcmp(fetchedKey2->get_key_data(), "Robi", fetchedKey2->get_key_data_size()) == 0);

    //check if the backup file was removed
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), TRUE);

    remove("./keyring.backup");
    remove(file_name.c_str());
    delete keys_container;
    delete logger;
    my_free(fetchedKey->release_key_data());
    my_free(fetchedKey2->release_key_data());
  }

  TEST_F(Keys_container_test_dont_close, BackupfileIsMalformedCheckItIsIgnoredAndDeleted)
  {
    ILogger *logger= new Mock_logger();
    IKeyring_io *keyring_io= new Buffered_file_io(logger);
    Keys_container *keys_container= new Keys_container(logger);

    EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
    //successfully stored the key - backup file does not exist
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);
    EXPECT_EQ(keys_container->store_key(sample_key2), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
    //Now we have correct backup file
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);

    delete keys_container;
    delete logger;
    generate_malformed_keyring_file_without_tag("./keyring.backup");
    logger= new Mock_logger();
    IKeyring_io *keyring_io_2= new Buffered_file_io(logger);
    keys_container= new Keys_container(logger);

    //Check that backup file was ignored (as backup file is malformed)
    EXPECT_CALL(*((Mock_logger *)logger), log(MY_WARNING_LEVEL, StrEq("Found malformed keyring backup file - removing it")));
    EXPECT_EQ(keys_container->init(keyring_io_2, file_name), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
    Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
    Key sample_key2_id("Roberts_key2", NULL, "Robert", NULL, 0);
    IKey *fetchedKey= keys_container->fetch_key(&sample_key2_id);
    ASSERT_TRUE(fetchedKey != NULL);
    ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_key2Robert");
    ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "xobi2", fetchedKey->get_key_data_size()) == 0);
    IKey *fetchedKey2= keys_container->fetch_key(&sample_key_id);
    ASSERT_TRUE(fetchedKey2 != NULL);
    ASSERT_TRUE(*fetchedKey2->get_key_signature() == "Roberts_keyRobert");
    ASSERT_TRUE(memcmp(fetchedKey2->get_key_data(), "Robi", fetchedKey2->get_key_data_size()) == 0);

    //check if the backup file was removed
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), TRUE);

    delete keys_container;
    delete logger;
    my_free(fetchedKey->release_key_data());
    my_free(fetchedKey2->release_key_data());
  }

  TEST_F(Keys_container_test_dont_close, CheckIfKeyringIsNotRecreatedWhenKeyringfileDoesnotExist)
  {
    Mock_logger *logger= new Mock_logger();
    IKeyring_io *keyring_io= new Buffered_file_io_dont_remove_backup(logger);
    Keys_container *keys_container= new Keys_container(logger);
    EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), TRUE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);

    remove("./keyring");
    remove("./keyring.backup");
    EXPECT_CALL(*logger,
                 log(MY_ERROR_LEVEL, StrEq("Could not flush keys to keyring's backup")));
    EXPECT_EQ(keys_container->store_key(sample_key2), 1);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), FALSE);

    Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
    IKey *fetchedKey= keys_container->fetch_key(&sample_key_id);
    ASSERT_TRUE(fetchedKey != NULL);

    ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_keyRobert");
    ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "Robi", fetchedKey->get_key_data_size()) == 0);

    remove(file_name.c_str());
    delete keys_container;
    delete logger;
    delete sample_key2;
    my_free(fetchedKey->release_key_data());
  }

  TEST_F(Keys_container_test_dont_close, CheckIfKeyringIsNotRecreatedWhenBackupFileExistsAndKeyringFileDoesnot)
  {
    Mock_logger *logger= new Mock_logger();
    IKeyring_io *keyring_io= new Buffered_file_io_dont_remove_backup(logger);
    Keys_container *keys_container= new Keys_container(logger);
    EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), TRUE);
    ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == TRUE);

    remove("./keyring");
    EXPECT_CALL(*logger,
                 log(MY_ERROR_LEVEL, StrEq("Could not flush keys to keyring's backup")));
    EXPECT_EQ(keys_container->store_key(sample_key2), 1);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

    //as the keyring file was removed keyring.backup file should have been truncated
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), FALSE);

    Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
    IKey *fetchedKey= keys_container->fetch_key(&sample_key_id);
    ASSERT_TRUE(fetchedKey != NULL);

    ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_keyRobert");
    ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "Robi", fetchedKey->get_key_data_size()) == 0);

    remove("./keyring.backup");
    remove(file_name.c_str());
    delete keys_container;
    delete logger;
    delete sample_key2;
    my_free(fetchedKey->release_key_data());
  }

  TEST_F(Keys_container_test_dont_close, CheckIfKeyIsNotDumpedIntoKeyringFileIfKeyringFileHasBeenChanged)
  {
    Mock_logger *logger= new Mock_logger();
    IKeyring_io *keyring_io_dont_remove_backup= new Buffered_file_io_dont_remove_backup(logger);
    Keys_container *keys_container= new Keys_container(logger);

    EXPECT_EQ(keys_container->init(keyring_io_dont_remove_backup, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), TRUE);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), TRUE);
    remove("./keyring");
    rename("keyring.backup","keyring");

    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), TRUE);

    EXPECT_CALL(*logger,
                log(MY_ERROR_LEVEL, StrEq("Keyring file has been changed outside the server.")));
    EXPECT_CALL(*logger,
                log(MY_ERROR_LEVEL, StrEq("Could not flush keys to keyring's backup")));
    EXPECT_EQ(keys_container->store_key(sample_key2), 1);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

    //check if backup file was not created
    EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), FALSE);
    delete keys_container;
    delete logger;
    delete sample_key2;
    remove("./keyring");
  }*/

  class Mock_vault_io : public IVault_io //TODO:Change it to Mock_vault_io
  {
  public:
    MOCK_METHOD1(retrieve_key_type_and_value, my_bool(IKey *key));
    MOCK_METHOD1(init, my_bool(std::string *keyring_filename));
    MOCK_METHOD1(flush_to_backup, my_bool(ISerialized_object *serialized_object));
    MOCK_METHOD1(flush_to_storage, my_bool(ISerialized_object *serialized_object));
    MOCK_METHOD0(get_serializer, ISerializer*());
    MOCK_METHOD1(get_serialized_object, my_bool(ISerialized_object **serialized_object));
    MOCK_METHOD0(has_next_serialized_object, my_bool());
  };

  class Mock_serialized_object : public ISerialized_object
  {
  public:
    MOCK_METHOD1(get_next_key, my_bool(IKey **key));
    MOCK_METHOD0(has_next_key, my_bool());
    MOCK_METHOD0(get_key_operation, Key_operation());
    MOCK_METHOD1(set_key_operation, void(Key_operation));
  };

  class Mock_serializer : public ISerializer
  {
  public:
    MOCK_METHOD3(serialize, ISerialized_object*(HASH*, IKey*, Key_operation));
  };

  class Vault_keys_container_with_mocked_io_test : public ::testing::Test
  {
  protected:
    virtual void SetUp()
    {
      std::string sample_key_data= "Robi";
      sample_key= new Vault_key("Roberts_key", "AES", "Robert", sample_key_data.c_str(), sample_key_data.length());
      credential_file_url = "./credentials";

//      remove(file_name.c_str());
//      remove("./keyring.backup");
/*
      correct_token = "8143069d-a3c0-9d72-b8a4-dcb29aab7de3"; //maybe this could be passed as a parameter to unit test ?
      credential_file_url = "./credentials";
      credential_file_was_created = false;
      logger= new Mock_logger();
      vault_keys_container= new Vault_keys_container(logger);


      std::string sample_key_data("Robi");
      sample_key= new Key("Roberts_key", "AES", "Robert", sample_key_data.c_str(), sample_key_data.length()+1);

      file_name= "/home/rob/write_key";*/
    }
    virtual void TearDown()
    {
//      remove(file_name.c_str());
      delete vault_keys_container;
    }
  protected:
    Vault_keys_container *vault_keys_container;
    Mock_vault_io *vault_io;
    Vault_key *sample_key;
    char* sample_key_data;
    std::string credential_file_url;

    void expect_calls_on_init();
    void expect_calls_on_store_sample_key();
  };

  void Vault_keys_container_with_mocked_io_test::expect_calls_on_init()
  {
    Mock_serialized_object *mock_serialized_object= new Mock_serialized_object;

    EXPECT_CALL(*vault_io, init(Pointee(StrEq(credential_file_url))))
      .WillOnce(Return(0)); // init successfull
    EXPECT_CALL(*vault_io, get_serialized_object(_))
      .WillOnce(DoAll(SetArgPointee<0>(mock_serialized_object), Return(FALSE)));
    EXPECT_CALL(*mock_serialized_object, has_next_key()).WillOnce(Return(FALSE)); // no keys to read
    EXPECT_CALL(*vault_io, has_next_serialized_object()).WillOnce(Return(FALSE));
  }

  TEST_F(Vault_keys_container_with_mocked_io_test, ErrorFromIODuringInitOnGettingSerializedObject)
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);

    EXPECT_CALL(*vault_io, init(Pointee(StrEq(credential_file_url))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_CALL(*vault_io, get_serialized_object(_)).WillOnce(Return(TRUE));
    EXPECT_CALL(*logger, log(MY_ERROR_LEVEL, StrEq("Error while loading keyring content. The keyring might be malformed")));

    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), TRUE);
    EXPECT_EQ(vault_keys_container->get_number_of_keys(), 0);
    delete logger;
    delete sample_key; //unused in this test
  }

  TEST_F(Vault_keys_container_with_mocked_io_test, ErrorFromIODuringInitInvalidKeyAndMockedSerializedObject)
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);

    IKey *invalid_key= new Vault_key();
    std::string invalid_key_type("ZZZ");
    invalid_key->set_key_type(&invalid_key_type);

    Mock_serialized_object *mock_serialized_object= new Mock_serialized_object;

    EXPECT_CALL(*vault_io, init(Pointee(StrEq(credential_file_url))))
      .WillOnce(Return(FALSE)); // init successfull
    {
      InSequence dummy;
      EXPECT_CALL(*vault_io, get_serialized_object(_)).WillOnce(DoAll(SetArgPointee<0>(mock_serialized_object), Return(FALSE)));
      EXPECT_CALL(*mock_serialized_object, has_next_key()).WillOnce(Return(TRUE));
      EXPECT_CALL(*mock_serialized_object, get_next_key(_)).WillOnce(DoAll(SetArgPointee<0>(sample_key), Return(FALSE)));
      EXPECT_CALL(*mock_serialized_object, has_next_key()).WillOnce(Return(TRUE));
      EXPECT_CALL(*mock_serialized_object, get_next_key(_)).WillOnce(DoAll(SetArgPointee<0>(invalid_key), Return(FALSE)));

      EXPECT_CALL(*logger, log(MY_ERROR_LEVEL, StrEq("Error while loading keyring content. The keyring might be malformed")));
   }

    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), TRUE);
    EXPECT_EQ(vault_keys_container->get_number_of_keys(), 0);
    delete logger;
  }

  TEST_F(Vault_keys_container_with_mocked_io_test, ErrorFromIODuringInitInvalidKey)
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);

    Vault_key *invalid_key= new Vault_key();
    std::string invalid_key_type("ZZZ");
    invalid_key->set_key_type(&invalid_key_type);

    Vault_keys_list *keys_list = new Vault_keys_list();
    keys_list->push_back(invalid_key);

    EXPECT_CALL(*vault_io, init(Pointee(StrEq(credential_file_url))))
      .WillOnce(Return(FALSE)); // init successfull
    {
      InSequence dummy;
      EXPECT_CALL(*vault_io, get_serialized_object(_)).WillOnce(DoAll(SetArgPointee<0>(keys_list), Return(FALSE)));
      EXPECT_CALL(*logger, log(MY_ERROR_LEVEL, StrEq("Error while loading keyring content. The keyring might be malformed")));
    }
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), TRUE);
    EXPECT_EQ(vault_keys_container->get_number_of_keys(), 0);
    delete logger;
//    delete invalid_key;
    delete sample_key; //unused in this test
  }

/*
  TEST_F(Keys_container_with_mocked_io_test, ErrorFromSerializerOnFlushToBackupWhenStoringKey)
  {
    keyring_io= new Mock_keyring_io();
    Mock_logger *logger= new Mock_logger();
    keys_container= new Keys_container(logger);
    expect_calls_on_init();
    EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
    Mock_serializer *mock_serializer= new Mock_serializer;

    {
      InSequence dummy;

      ISerialized_object *null_serialized_object= NULL;
      EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,NULL,NONE))
        .WillOnce(Return(null_serialized_object));
      EXPECT_CALL(*logger, log(MY_ERROR_LEVEL, StrEq("Could not flush keys to keyring's backup")));
    }
    EXPECT_EQ(keys_container->store_key(sample_key), 1);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 0);

    delete logger;
    delete sample_key;
    delete mock_serializer;
  }
*/
  TEST_F(Vault_keys_container_with_mocked_io_test, ErrorFromSerializerOnFlushToKeyringWhenStoringKey)
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);
    expect_calls_on_init();
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), FALSE);
    EXPECT_EQ(vault_keys_container->get_number_of_keys(), 0);
    Mock_serializer *mock_serializer= new Mock_serializer;

//    ISerialized_object *empty_serialized_object= new Vault_keys_list();

    {
      InSequence dummy;
      ISerialized_object *null_serialized_object= NULL;
      //flush to backup
/*      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,NULL,NONE))
        .WillOnce(Return(empty_serialized_object));*/
//      EXPECT_CALL(*vault_io, flush_to_backup(empty_serialized_object));
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,STORE_KEY))
        .WillOnce(Return(null_serialized_object));
      EXPECT_CALL(*logger, log(MY_ERROR_LEVEL, StrEq("Could not flush keys to keyring")));
    }
    EXPECT_EQ(vault_keys_container->store_key(sample_key), TRUE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);

    delete logger;
    delete sample_key;
    delete mock_serializer;
  }
/*
  TEST_F(Keys_container_with_mocked_io_test, ErrorFromSerializerOnFlushToBackupWhenRemovingKey)
  {
    keyring_io= new Mock_keyring_io();
    Mock_logger *logger= new Mock_logger();
    keys_container= new Keys_container(logger);
    expect_calls_on_init();
    EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
    Mock_serializer *mock_serializer= new Mock_serializer;

    ISerialized_object *empty_serialized_object= new Buffer;
    Buffer *serialized_object_with_sample_key= new Buffer(sample_key->get_key_pod_size());
    sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                                &(serialized_object_with_sample_key->position));
    serialized_object_with_sample_key->position= 0; //rewind buffer

    {
      InSequence dummy;
      //flush to backup
      EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,NULL,NONE))
        .WillOnce(Return(empty_serialized_object));
      EXPECT_CALL(*keyring_io, flush_to_backup(empty_serialized_object));
      //flush to keyring
      EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,STORE_KEY))
        .WillOnce(Return(serialized_object_with_sample_key));
      EXPECT_CALL(*keyring_io, flush_to_storage(serialized_object_with_sample_key));
    }
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

    {
      InSequence dummy;
      ISerialized_object *null_serialized_object= NULL;

      EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,NULL,NONE))
        .WillOnce(Return(null_serialized_object));
      EXPECT_CALL(*logger, log(MY_ERROR_LEVEL, StrEq("Could not flush keys to keyring's backup")));
    }
    EXPECT_EQ(keys_container->remove_key(sample_key), 1);
    ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

    delete logger;
    delete mock_serializer;
  }
*/
  TEST_F(Vault_keys_container_with_mocked_io_test, ErrorFromSerializerOnFlushToKeyringWhenRemovingKey)
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);
    expect_calls_on_init();
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), FALSE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);
    Mock_serializer *mock_serializer= new Mock_serializer;

    Vault_key *serialized_sample_key = new Vault_key(*sample_key);

    {
      InSequence dummy;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,STORE_KEY))
        .WillOnce(Return(serialized_sample_key));
      EXPECT_CALL(*vault_io, flush_to_storage(serialized_sample_key));
    }
    EXPECT_EQ(vault_keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    {
      InSequence dummy;
      ISerialized_object *null_serialized_object= NULL;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,REMOVE_KEY))
        .WillOnce(Return(null_serialized_object));
      EXPECT_CALL(*logger, log(MY_ERROR_LEVEL, StrEq("Could not flush keys to keyring")));
    }

    EXPECT_EQ(vault_keys_container->remove_key(sample_key), 1);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    delete logger;
    delete mock_serializer;
  }

  TEST_F(Vault_keys_container_with_mocked_io_test, StoreAndRemoveKey) //TODO: Add fetch operation
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);
    expect_calls_on_init();
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), FALSE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);
    Mock_serializer *mock_serializer= new Mock_serializer;

    Vault_key *serialized_sample_key = new Vault_key(*sample_key);
 
    {
      InSequence dummy;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,STORE_KEY))
        .WillOnce(Return(serialized_sample_key));
      EXPECT_CALL(*vault_io, flush_to_storage(serialized_sample_key))
	.WillOnce(Return(FALSE));
    }
    sample_key->set_key_operation(STORE_KEY);
    EXPECT_EQ(vault_keys_container->store_key(sample_key), FALSE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    Vault_key *serialized_sample_key_to_remove = new Vault_key(*sample_key);

    serialized_sample_key_to_remove->set_key_operation(REMOVE_KEY);
    {
      InSequence dummy;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,REMOVE_KEY))
        .WillOnce(Return(serialized_sample_key_to_remove));
      EXPECT_CALL(*vault_io, flush_to_storage(serialized_sample_key_to_remove));
    }
    sample_key->set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_keys_container->remove_key(sample_key), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);

    delete logger;
    delete mock_serializer;
  }

  TEST_F(Vault_keys_container_with_mocked_io_test, ErrorFromIOWhileRemovingKeyAfterAdding2Keys)
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);
    expect_calls_on_init();
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), FALSE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);
    Mock_serializer *mock_serializer= new Mock_serializer;

    Vault_key *serialized_sample_key = new Vault_key(*sample_key);

    {
      InSequence dummy;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,STORE_KEY))
        .WillOnce(Return(serialized_sample_key));
      EXPECT_CALL(*vault_io, flush_to_storage(serialized_sample_key));
    }
    EXPECT_EQ(vault_keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    std::string key_data2("Robi2");
    Vault_key *key2= new Vault_key("Roberts_key2", "AES", "Robert", key_data2.c_str(), key_data2.length());

    Vault_key *serialized_key2 = new Vault_key(*key2);

    {
      InSequence dummy;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,key2,STORE_KEY))
        .WillOnce(Return(serialized_key2));
      EXPECT_CALL(*vault_io, flush_to_storage(serialized_key2));
    }
    EXPECT_EQ(vault_keys_container->store_key(key2), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 2);

    {
      InSequence dummy;
      ISerialized_object *null_serialized_object= NULL;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,REMOVE_KEY))
        .WillOnce(Return(null_serialized_object));
      EXPECT_CALL(*logger, log(MY_ERROR_LEVEL, StrEq("Could not flush keys to keyring")));
    }

    EXPECT_EQ(vault_keys_container->remove_key(sample_key), TRUE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 2);

    delete logger;
    delete mock_serializer;
  }

  TEST_F(Vault_keys_container_with_mocked_io_test, Store2KeysAndRemoveThem)
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);
    expect_calls_on_init();
    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), FALSE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);
    Mock_serializer *mock_serializer= new Mock_serializer;

    sample_key->set_key_operation(STORE_KEY);
    Vault_key *serialized_sample_key = new Vault_key(*sample_key);

    {
      InSequence dummy;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,STORE_KEY))
        .WillOnce(Return(serialized_sample_key));
      EXPECT_CALL(*vault_io, flush_to_storage(serialized_sample_key));
    }
    EXPECT_EQ(vault_keys_container->store_key(sample_key), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    std::string key_data2("Robi2");
    Vault_key *key2= new Vault_key("Roberts_key2", "AES", "Robert", key_data2.c_str(), key_data2.length());
    key2->set_key_operation(STORE_KEY);

    Vault_key *serialized_key2 = new Vault_key(*key2);

    {
      InSequence dummy;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,key2,STORE_KEY))
        .WillOnce(Return(serialized_key2));
      EXPECT_CALL(*vault_io, flush_to_storage(serialized_key2));
    }
    EXPECT_EQ(vault_keys_container->store_key(key2), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 2);

    sample_key->set_key_operation(REMOVE_KEY);

    Vault_key *serialized_sample_key_to_remove = new Vault_key(*sample_key);

    {
      InSequence dummy;
      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,sample_key,REMOVE_KEY))
        .WillOnce(Return(serialized_sample_key_to_remove));
      EXPECT_CALL(*vault_io, flush_to_storage(serialized_sample_key_to_remove));
    }

    sample_key->set_key_operation(REMOVE_KEY);
    EXPECT_EQ(vault_keys_container->remove_key(sample_key), FALSE);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 1);

    key2->set_key_operation(REMOVE_KEY);
    Vault_key *serialized_key2_to_remove = new Vault_key(*key2);

    {
      InSequence dummy;

      //flush to keyring
      EXPECT_CALL(*vault_io, get_serializer())
        .WillOnce(Return(mock_serializer));
      EXPECT_CALL(*mock_serializer, serialize(_,key2,REMOVE_KEY))
        .WillOnce(Return(serialized_key2_to_remove));
      EXPECT_CALL(*vault_io, flush_to_storage(serialized_key2_to_remove));
    }

    EXPECT_EQ(vault_keys_container->remove_key(key2), 0);
    ASSERT_TRUE(vault_keys_container->get_number_of_keys() == 0);

    delete logger;
    delete mock_serializer;
  }

  TEST_F(Vault_keys_container_with_mocked_io_test, ErrorFromRetriveKeyTypeDuringFetch) //TODO: Next test that retrieve is not called when key is fetched for the 2nd time
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);

    Vault_key *key_from_list = new Vault_key("key1", NULL, "Robert", NULL, 0);

    EXPECT_CALL(*vault_io, init(Pointee(StrEq(credential_file_url))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_CALL(*vault_io, get_serialized_object(_))
      .WillOnce(DoAll(SetArgPointee<0>(key_from_list), Return(FALSE)));
    EXPECT_CALL(*vault_io, has_next_serialized_object()).WillOnce(Return(FALSE)); //just one key

    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), FALSE);
    EXPECT_EQ(vault_keys_container->get_number_of_keys(),1);

    Vault_key key_fetched("key1", NULL, "Robert", NULL, 0);
    ASSERT_TRUE(key_fetched.get_key_data() == NULL);

    EXPECT_CALL(*vault_io, retrieve_key_type_and_value(_))
      .WillOnce(Return(TRUE));
    //retrieving key for the first time - key's data and type is kept only in Vault
    //need to fetch them on container's fetch operation
    EXPECT_EQ(vault_keys_container->fetch_key(&key_fetched), (IKey*)0);

    delete logger;
    delete sample_key;
  }

  void set_data(IKey *key)
  {
    std::string type("AES");
    key->set_key_type(&type);
    uchar *data = new uchar[2];//{'1','2','3','4'};
    data[0] = 'a';
    data[1] = 'b';
    key->set_key_data(data, 2);
  }

  TEST_F(Vault_keys_container_with_mocked_io_test, CheckThatRetriveKeyTypeIsNotCalledForSecondFetch)
  {
    vault_io= new Mock_vault_io();
    Mock_logger *logger= new Mock_logger();
    vault_keys_container= new Vault_keys_container(logger);

    Vault_key *key_from_list = new Vault_key("key1", NULL, "Robert", NULL, 0);

    EXPECT_CALL(*vault_io, init(Pointee(StrEq(credential_file_url))))
      .WillOnce(Return(FALSE)); // init successfull
    EXPECT_CALL(*vault_io, get_serialized_object(_))
      .WillOnce(DoAll(SetArgPointee<0>(key_from_list), Return(FALSE)));
    EXPECT_CALL(*vault_io, has_next_serialized_object()).WillOnce(Return(FALSE)); //just one key

    EXPECT_EQ(vault_keys_container->init(vault_io, credential_file_url), FALSE);
    EXPECT_EQ(vault_keys_container->get_number_of_keys(),1);

    Vault_key key_to_fetch("key1", NULL, "Robert", NULL, 0);
    ASSERT_TRUE(key_to_fetch.get_key_data() == NULL);
    //IKey *key_fetched_from_vault = new Vault_key("key1", "AES", "Robert", "01234", 5);
    IKey *key_fetched_from_keyring;
    //IKey *key_fetched_from_hash = NULL;

    EXPECT_CALL(*vault_io, retrieve_key_type_and_value(_))
      //.WillOnce(DoAll(testing::SaveArg<0>(key_fetched_from_hash), Return(FALSE)));
      .WillOnce(DoAll(WithArgs<0>(Invoke(set_data)), Return(FALSE)));
    //retrieving key for the first time - key's data and type is kept only in Vault
    //need to fetch them on container's fetch operation
    key_fetched_from_keyring = vault_keys_container->fetch_key(&key_to_fetch);
    //TODO: check key's signature
    //key_fetched_from_hash->set_key_type(key_fetched_from_keyring->get_key_type());
    //key_fetched_from_hash->set_key_data(key_fetched_from_keyring->get_key_data(), key_fetched_from_keyring->get_key_data_size());
    
    //When we call fetch_key for the 2nd time - key's data and type should be already cached
    //thus the second call should not call retrieve_key_type_and_value
    Vault_key key_to_fetch2("key2", NULL, "Robert", NULL, 0);
    EXPECT_CALL(*vault_io, retrieve_key_type_and_value(_)).Times(0);
    key_fetched_from_keyring = vault_keys_container->fetch_key(&key_to_fetch2);

    my_free(key_to_fetch.release_key_data());
    my_free(key_to_fetch2.release_key_data());
    delete logger;
    delete sample_key; //unused in this test
  }


/*  int main(int argc, char **argv) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    ::testing::InitGoogleTest(&argc, argv);
    #ifdef HAVE_PSI_INTERFACE
    if (mysql_rwlock_init(keyring::key_LOCK_keyring, &LOCK_keyring))
      return TRUE;
    #endif
    int ret= RUN_ALL_TESTS();
    curl_global_cleanup();
    return ret;
  }*/
}


