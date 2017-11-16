/* Copyright (c) 2016, 2018, Oracle and/or its affiliates. All rights reserved.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License, version 2.0,
   as published by the Free Software Foundation.

   This program is also distributed with certain software (including
   but not limited to OpenSSL) that is licensed under separate terms,
   as designated in a particular file or component or in included license
   documentation.  The authors of MySQL hereby grant you an additional
   permission to link the program and your derivative works with the
   separately licensed software that they have included with MySQL.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License, version 2.0, for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <mysql/plugin_keyring.h>
#include <fstream>

#include "my_inttypes.h"
#include "plugin/keyring/buffered_file_io.h"
#include "plugin/keyring/common/i_serialized_object.h"
#include "plugin/keyring/common/keyring.h"
#include "plugin/keyring/common/keys_container.h"
#include "unittest/gunit/keyring/buffered_file_io_10.h"
#include "unittest/gunit/keyring/mock_logger.h"

namespace keyring__keys_container_unittest {
using namespace keyring;
using ::testing::DoAll;
using ::testing::InSequence;
using ::testing::Return;
using ::testing::SetArgPointee;
using ::testing::StrEq;
using ::testing::_;

bool check_if_file_exists_and_TAG_is_correct(const char *file_name) {
  char tag[4];
  std::fstream file;

  file.open(file_name, std::fstream::in | std::fstream::binary);
  if (!file.is_open()) return false;
  file.seekg(0, file.end);
  if (file.tellg() < (3 + 32))  // tag + sha256
    return false;               // File do not contains tag
  file.seekg(-(3 + 32), file.end);
  if (file.good() == false) return false;
  file.read(tag, 3);
  size_t chars_read = file.gcount();
  if (file.good() == false || chars_read < 3) return false;
  tag[3] = '\0';
  file.close();
  return strcmp(tag, "EOF") == 0;
}

class Keys_container_test : public ::testing::Test {
 public:
  Keys_container_test() : file_name("./keyring") {}

 protected:
  virtual void SetUp() {
    sample_key_data = "Robi";
    sample_key = new Key("Roberts_key", "AES", "Robert",
                         sample_key_data.c_str(), sample_key_data.length() + 1);

    remove(file_name.c_str());
    remove("./keyring.backup");

    logger = new Mock_logger();
    keys_container = new Keys_container(logger);
  }
  virtual void TearDown() {
    remove(file_name.c_str());
    delete keys_container;
    delete logger;
  }
  void create_keyring_file(const char *file_name, const char *keyring_buffer);
  void generate_keyring_file_with_correct_ver_1_0_structure(
      const char *file_name);
  void generate_keyring_file_with_correct_ver_2_0_structure(
      const char *file_name);
  void generate_keyring_file_with_incorrect_file_version(const char *file_name);
  void generate_keyring_file_with_incorrect_TAG(const char *file_name);

 protected:
  Keys_container *keys_container;
  ILogger *logger;
  Key *sample_key;
  std::string sample_key_data;
  std::string file_name;
};

void Keys_container_test::create_keyring_file(const char *file_name,
                                              const char *keyring_buffer) {
  std::fstream file;
  file.open(file_name,
            std::fstream::out | std::fstream::binary | std::fstream::trunc);
  ASSERT_TRUE(file.is_open());
  file.write(keyring_buffer, strlen(keyring_buffer));
  file.close();
}

void Keys_container_test::generate_keyring_file_with_correct_ver_1_0_structure(
    const char *file_name) {
  static const char *keyring_buffer = "Keyring file version:1.0EOF";
  create_keyring_file(file_name, keyring_buffer);
}

void Keys_container_test::generate_keyring_file_with_correct_ver_2_0_structure(
    const char *file_name) {
  static const char *keyring_buffer =
      "Keyring file version:2.0EOF"
      "01234567890123456789012345678901";
  create_keyring_file(file_name, keyring_buffer);
}

void Keys_container_test::generate_keyring_file_with_incorrect_file_version(
    const char *file_name) {
  static const char *keyring_buffer = "Keyring file version:3.0EOF";
  create_keyring_file(file_name, keyring_buffer);
}

void Keys_container_test::generate_keyring_file_with_incorrect_TAG(
    const char *file_name) {
  static const char *keyring_buffer = "Keyring file version:2.0EF";
  create_keyring_file(file_name, keyring_buffer);
}

TEST_F(Keys_container_test, InitWithFileWithCorrect_1_0_Struct) {
  const char *keyring_correct_struct = "./keyring_correct_1_0_struct";
  remove(keyring_correct_struct);
  std::vector<std::string> allowedFileVersionsToInit;
  // this keyring will work with keyring files in the following versions:
  allowedFileVersionsToInit.push_back(keyring::keyring_file_version_2_0);
  allowedFileVersionsToInit.push_back(keyring::keyring_file_version_1_0);
  generate_keyring_file_with_correct_ver_1_0_structure(keyring_correct_struct);
  IKeyring_io *keyring_io =
      new Buffered_file_io(logger, &allowedFileVersionsToInit);
  EXPECT_EQ(keys_container->init(keyring_io, keyring_correct_struct), 0);
  remove(keyring_correct_struct);
  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_test, InitWithFileWithCorrect_2_0_Struct) {
  const char *keyring_correct_struct = "./keyring_correct_2_0_struct";
  remove(keyring_correct_struct);
  generate_keyring_file_with_correct_ver_2_0_structure(keyring_correct_struct);
  Buffered_file_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, keyring_correct_struct), 0);
  remove(keyring_correct_struct);
  delete sample_key;  // unused in this test
}

// HAVE_UBSAN: undefined behaviour in gmock.
#if !defined(HAVE_UBSAN)
TEST_F(Keys_container_test, InitWithFileWithIncorrectKeyringVersion) {
  const char *keyring_incorrect_version = "./keyring_incorrect_version";
  remove(keyring_incorrect_version);
  generate_keyring_file_with_incorrect_file_version(keyring_incorrect_version);
  Buffered_file_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_CALL(*((Mock_logger *)logger),
              log(ERROR_LEVEL, StrEq("Incorrect Keyring file")));
  EXPECT_CALL(*((Mock_logger *)logger),
              log(ERROR_LEVEL, StrEq("Error while loading keyring content."
                                     " The keyring might be malformed")));
  EXPECT_EQ(keys_container->init(keyring_io, keyring_incorrect_version), 1);
  remove(keyring_incorrect_version);
  delete sample_key;  // unused in this test
}
#endif  // HAVE_UBSAN

TEST_F(Keys_container_test, InitWithFileWithIncorrectTAG) {
  const char *keyring_incorrect_tag = "./keyring_incorrect_tag";
  remove(keyring_incorrect_tag);
  generate_keyring_file_with_incorrect_TAG(keyring_incorrect_tag);
  Buffered_file_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_CALL(*((Mock_logger *)logger),
              log(ERROR_LEVEL, StrEq("Incorrect Keyring file")));
  EXPECT_CALL(*((Mock_logger *)logger),
              log(ERROR_LEVEL, StrEq("Error while loading keyring content. The "
                                     "keyring might be malformed")));
  EXPECT_EQ(keys_container->init(keyring_io, keyring_incorrect_tag), 1);
  remove(keyring_incorrect_tag);
  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_test, StoreFetchRemove) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  Key key_id("Roberts_key", NULL, "Robert", NULL, 0);
  IKey *fetched_key = keys_container->fetch_key(&key_id);

  ASSERT_TRUE(fetched_key != NULL);
  std::string expected_key_signature = "Roberts_keyRobert";
  EXPECT_STREQ(fetched_key->get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(fetched_key->get_key_signature()->length(),
            expected_key_signature.length());
  uchar *key_data_fetched = fetched_key->get_key_data();
  size_t key_data_fetched_size = fetched_key->get_key_data_size();
  EXPECT_STREQ(sample_key_data.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
  ASSERT_TRUE(sample_key_data.length() + 1 == key_data_fetched_size);

  keys_container->remove_key(&key_id);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  my_free(fetched_key->release_key_data());
}

TEST_F(Keys_container_test, FetchNotExisting) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  Key key_id("Roberts_key", NULL, "Robert", NULL, 0);
  IKey *fetched_key = keys_container->fetch_key(&key_id);
  ASSERT_TRUE(fetched_key == NULL);
  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_test, RemoveNotExisting) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  Key key_id("Roberts_key", "AES", "Robert", NULL, 0);
  ASSERT_TRUE(keys_container->remove_key(&key_id) == true);
  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_test, StoreFetchNotExisting) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  Key key_id("NotRoberts_key", NULL, "NotRobert", NULL, 0);
  IKey *fetched_key = keys_container->fetch_key(&key_id);
  ASSERT_TRUE(fetched_key == NULL);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
}

TEST_F(Keys_container_test, StoreRemoveNotExisting) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  Key key_id("NotRoberts_key", "AES", "NotRobert", NULL, 0);
  // Failed to remove key
  ASSERT_TRUE(keys_container->remove_key(&key_id) == true);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
}

TEST_F(Keys_container_test, StoreStoreStoreFetchRemove) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  std::string key_data1("Robi1");
  Key *key1 = new Key("Roberts_key1", "AES", "Robert", key_data1.c_str(),
                      key_data1.length() + 1);

  EXPECT_EQ(keys_container->store_key(key1), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  std::string key_data2("Robi2");
  Key *key2 = new Key("Roberts_key2", "AES", "Robert", key_data2.c_str(),
                      key_data2.length() + 1);

  EXPECT_EQ(keys_container->store_key(key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);

  std::string key_data3("Robi3");
  Key *key3 = new Key("Roberts_key3", "AES", "Robert", key_data3.c_str(),
                      key_data3.length() + 1);

  EXPECT_EQ(keys_container->store_key(key3), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 4);

  Key key2_id("Roberts_key2", NULL, "Robert", NULL, 0);
  IKey *fetched_key = keys_container->fetch_key(&key2_id);

  ASSERT_TRUE(fetched_key != NULL);
  std::string expected_key_signature = "Roberts_key2Robert";
  EXPECT_STREQ(fetched_key->get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(fetched_key->get_key_signature()->length(),
            expected_key_signature.length());
  uchar *key_data_fetched = fetched_key->get_key_data();
  size_t key_data_fetched_size = fetched_key->get_key_data_size();
  EXPECT_STREQ(key_data2.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  ASSERT_TRUE(key_data2.length() + 1 == key_data_fetched_size);

  Key key3_id("Roberts_key3", "AES", "Robert", NULL, 0);
  keys_container->remove_key(&key3_id);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);

  my_free(fetched_key->release_key_data());
}

TEST_F(Keys_container_test,
       StorePBStorePBStorePBStoreIK1StoreIK2FetchPBFetchIK) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);

  std::string key_data1("system_key_data_1");
  Key *key1 = new Key("percona_binlog:0", "AES", nullptr, key_data1.c_str(),
                      key_data1.length() + 1);
  key1->xor_data();
  EXPECT_EQ(keys_container->store_key(key1), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  std::string key_data2("system_key_data_2");
  Key *key2 = new Key("percona_binlog:1", "AES", nullptr, key_data2.c_str(),
                      key_data2.length() + 1);
  key2->xor_data();
  EXPECT_EQ(keys_container->store_key(key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  std::string key_data3("system_key_data_3");
  Key *key3 = new Key("percona_binlog:2", "AES", nullptr, key_data3.c_str(),
                      key_data3.length() + 1);
  key3->xor_data();
  EXPECT_EQ(keys_container->store_key(key3), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);

  std::string ik_data1("data1");

  Key *innodb_key1 = new Key("percona_innodb1_2_3:0:0", "AES", nullptr,
                             ik_data1.c_str(), ik_data1.length() + 1);
  innodb_key1->xor_data();
  EXPECT_EQ(keys_container->store_key(innodb_key1), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 4);

  std::string ik_data2("data2");

  Key *innodb_key2 = new Key("percona_innodb1_2_3:0:1", "AES", nullptr,
                             ik_data2.c_str(), ik_data2.length() + 1);
  innodb_key2->xor_data();
  EXPECT_EQ(keys_container->store_key(innodb_key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 5);

  Key latest_percona_binlog_key("percona_binlog", nullptr, nullptr, nullptr, 0);
  IKey *fetched_key = keys_container->fetch_key(&latest_percona_binlog_key);
  ASSERT_TRUE(fetched_key != nullptr);

  Key key(fetched_key->get_key_id()->c_str(),
          fetched_key->get_key_type()->c_str(),
          fetched_key->get_user_id()->c_str(), fetched_key->get_key_data(),
          fetched_key->get_key_data_size());
  key.xor_data();

  std::string expected_key_signature = "percona_binlog";
  EXPECT_STREQ(key.get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(key.get_key_signature()->length(), expected_key_signature.length());
  uchar *key_data_fetched = key.get_key_data();
  size_t key_data_fetched_size = key.get_key_data_size();
  std::string key_data_with_version = "2:" + key_data3;
  EXPECT_STREQ(key_data_with_version.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
  ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

  Key latest_innodb_key("percona_innodb1_2_3:0", nullptr, nullptr, nullptr, 0);
  IKey *fetched_innodb_key = keys_container->fetch_key(&latest_innodb_key);
  ASSERT_TRUE(fetched_innodb_key != nullptr);

  Key innodb_key(fetched_innodb_key->get_key_id()->c_str(),
                 fetched_innodb_key->get_key_type()->c_str(),
                 fetched_innodb_key->get_user_id()->c_str(),
                 fetched_innodb_key->get_key_data(),
                 fetched_innodb_key->get_key_data_size());
  innodb_key.xor_data();

  expected_key_signature = "percona_innodb1_2_3:0";
  EXPECT_STREQ(innodb_key.get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(innodb_key.get_key_signature()->length(),
            expected_key_signature.length());
  key_data_fetched = innodb_key.get_key_data();
  key_data_fetched_size = innodb_key.get_key_data_size();
  key_data_with_version = "1:" + ik_data2;
  EXPECT_STREQ(key_data_with_version.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
  ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

  my_free(fetched_key->release_key_data());
  my_free(fetched_innodb_key->release_key_data());

  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_test,
       StorePBRotatePBFetchPBStoreSKRotatePBFetchPBRotateSKFetchSK) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), false);

  std::string key_data1("system_key_data_1");
  Key *key1 = new Key("percona_binlog:0", "AES", nullptr, key_data1.c_str(),
                      key_data1.length() + 1);
  key1->xor_data();

  EXPECT_EQ(keys_container->store_key(key1), false);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  std::string key_data2("system_key_data_2");
  Key *percona_binlog_rotation =
      new Key("percona_binlog", "AES", nullptr, key_data2.c_str(),
              key_data2.length() + 1);
  percona_binlog_rotation->xor_data();
  EXPECT_EQ(keys_container->store_key(percona_binlog_rotation), false);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  Key latest_percona_binlog_key("percona_binlog", nullptr, nullptr, nullptr, 0);
  IKey *fetched_key = keys_container->fetch_key(&latest_percona_binlog_key);

  ASSERT_TRUE(fetched_key != nullptr);

  Key key(fetched_key->get_key_id()->c_str(),
          fetched_key->get_key_type()->c_str(),
          fetched_key->get_user_id()->c_str(), fetched_key->get_key_data(),
          fetched_key->get_key_data_size());
  key.xor_data();

  std::string expected_key_signature = "percona_binlog";
  EXPECT_STREQ(key.get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(key.get_key_signature()->length(), expected_key_signature.length());
  uchar *key_data_fetched = key.get_key_data();
  size_t key_data_fetched_size = key.get_key_data_size();
  std::string key_data_with_version = "1:" + key_data2;
  EXPECT_STREQ(key_data_with_version.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
  ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

  std::string sk_data1("sk_data_1");
  Key *sys_key1 = new Key("percona_sk:0", "AES", nullptr, sk_data1.c_str(),
                          sk_data1.length() + 1);
  sys_key1->xor_data();

  EXPECT_EQ(keys_container->store_key(sys_key1), false);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);

  std::string key_data3("system_key_data_3");
  Key *percona_binlog_rotation1_to_2 =
      new Key("percona_binlog", "AES", nullptr, key_data3.c_str(),
              key_data3.length() + 1);
  percona_binlog_rotation1_to_2->xor_data();
  EXPECT_EQ(keys_container->store_key(percona_binlog_rotation1_to_2), false);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 4);

  Key latest_percona_binlog_key_2("percona_binlog", nullptr, nullptr, nullptr,
                                  0);
  IKey *fetched_key_2 = keys_container->fetch_key(&latest_percona_binlog_key_2);

  ASSERT_TRUE(fetched_key_2 != nullptr);

  Key key_2(fetched_key_2->get_key_id()->c_str(),
            fetched_key_2->get_key_type()->c_str(),
            fetched_key_2->get_user_id()->c_str(),
            fetched_key_2->get_key_data(), fetched_key_2->get_key_data_size());
  key_2.xor_data();

  EXPECT_STREQ(key_2.get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(key_2.get_key_signature()->length(),
            expected_key_signature.length());
  key_data_fetched = key_2.get_key_data();
  key_data_fetched_size = key_2.get_key_data_size();
  key_data_with_version = "2:" + key_data3;
  EXPECT_STREQ(key_data_with_version.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
  ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

  std::string key_data4("system_key_data_4");
  Key *percona_binlog_rotation2_to_3 =
      new Key("percona_binlog", "AES", nullptr, key_data4.c_str(),
              key_data4.length() + 1);
  percona_binlog_rotation2_to_3->xor_data();
  EXPECT_EQ(keys_container->store_key(percona_binlog_rotation2_to_3), false);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 5);

  Key latest_percona_binlog_key_3("percona_binlog", nullptr, nullptr, nullptr,
                                  0);
  IKey *fetched_key_3 = keys_container->fetch_key(&latest_percona_binlog_key_3);

  ASSERT_TRUE(fetched_key_3 != nullptr);

  Key key_3(fetched_key_3->get_key_id()->c_str(),
            fetched_key_3->get_key_type()->c_str(),
            fetched_key_3->get_user_id()->c_str(),
            fetched_key_3->get_key_data(), fetched_key_3->get_key_data_size());
  key_3.xor_data();

  EXPECT_STREQ(key_3.get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(key_3.get_key_signature()->length(),
            expected_key_signature.length());
  key_data_fetched = key_3.get_key_data();
  key_data_fetched_size = key_3.get_key_data_size();
  key_data_with_version = "3:" + key_data4;
  EXPECT_STREQ(key_data_with_version.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
  ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

  std::string sk_data2("sk_data_2");
  Key *percona_sk_rotation1_to_2 = new Key(
      "percona_sk", "AES", nullptr, sk_data2.c_str(), sk_data2.length() + 1);
  percona_sk_rotation1_to_2->xor_data();
  EXPECT_EQ(keys_container->store_key(percona_sk_rotation1_to_2), false);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 6);

  Key latest_sk("percona_sk", nullptr, nullptr, nullptr, 0);
  IKey *fetched_sk = keys_container->fetch_key(&latest_sk);

  ASSERT_TRUE(fetched_sk != nullptr);

  Key sk(fetched_sk->get_key_id()->c_str(), fetched_sk->get_key_type()->c_str(),
         fetched_sk->get_user_id()->c_str(), fetched_sk->get_key_data(),
         fetched_sk->get_key_data_size());
  sk.xor_data();

  expected_key_signature = "percona_sk";
  EXPECT_STREQ(sk.get_key_signature()->c_str(), expected_key_signature.c_str());
  EXPECT_EQ(sk.get_key_signature()->length(), expected_key_signature.length());
  key_data_fetched = sk.get_key_data();
  key_data_fetched_size = sk.get_key_data_size();
  key_data_with_version = "1:" + sk_data2;
  EXPECT_STREQ(key_data_with_version.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  EXPECT_STREQ("AES", fetched_sk->get_key_type()->c_str());
  ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

  my_free(fetched_key->release_key_data());
  my_free(fetched_key_2->release_key_data());
  my_free(fetched_key_3->release_key_data());
  my_free(fetched_sk->release_key_data());

  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_test, StoreStoreStoreSystemKeyAndTryRemovingSystemKey) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);

  std::string key_data1("system_key_data_1");
  Key *key1 = new Key("percona_binlog:0", "AES", nullptr, key_data1.c_str(),
                      key_data1.length() + 1);

  EXPECT_EQ(keys_container->store_key(key1), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  std::string key_data2("system_key_data_2");
  Key *key2 = new Key("percona_binlog:1", "AES", nullptr, key_data2.c_str(),
                      key_data2.length() + 1);
  EXPECT_EQ(keys_container->store_key(key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  std::string key_data3("system_key_data_3");
  Key *key3 = new Key("percona_binlog:2", "AES", nullptr, key_data3.c_str(),
                      key_data3.length() + 1);
  EXPECT_EQ(keys_container->store_key(key3), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);

  Key latest_percona_binlog_key("percona_binlog:2", nullptr, nullptr, nullptr,
                                0);
  ASSERT_TRUE(keys_container->remove_key(&latest_percona_binlog_key) == true);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);

  Key percona_binlog_key("percona_binlog", nullptr, nullptr, nullptr, 0);
  ASSERT_TRUE(keys_container->remove_key(&percona_binlog_key) == true);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);

  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_test,
       StoreStoreStoreRemoveFetchSystemKeyFetchRegularKey) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);

  std::string key_data1("system_key_data_1");
  Key *key1 = new Key("percona_binlog:0", "AES", nullptr, key_data1.c_str(),
                      key_data1.length() + 1);

  EXPECT_EQ(keys_container->store_key(key1), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  std::string key_data2("system_key_data_2");
  Key *key2 = new Key("percona_binlog:1", "AES", nullptr, key_data2.c_str(),
                      key_data2.length() + 1);
  key2->xor_data();
  EXPECT_EQ(keys_container->store_key(key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  std::string key_data3("Robi3");
  Key *key3 = new Key("Roberts_key3", "AES", "Robert", key_data3.c_str(),
                      key_data3.length() + 1);
  EXPECT_EQ(keys_container->store_key(key3), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);

  std::string key_data4("Robi4");
  Key *key4 = new Key("Roberts_key4", "AES", "Robert", key_data4.c_str(),
                      key_data4.length() + 1);
  EXPECT_EQ(keys_container->store_key(key4), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 4);

  Key key3_id("Roberts_key3", "AES", "Robert", nullptr, 0);
  keys_container->remove_key(&key3_id);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);

  Key latest_percona_binlog_key("percona_binlog", nullptr, nullptr, nullptr, 0);
  IKey *fetched_key = keys_container->fetch_key(&latest_percona_binlog_key);

  ASSERT_TRUE(fetched_key != nullptr);

  Key key(fetched_key->get_key_id()->c_str(),
          fetched_key->get_key_type()->c_str(),
          fetched_key->get_user_id()->c_str(), fetched_key->get_key_data(),
          fetched_key->get_key_data_size());
  key.xor_data();

  std::string expected_key_signature = "percona_binlog";
  EXPECT_STREQ(key.get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(key.get_key_signature()->length(), expected_key_signature.length());
  uchar *key_data_fetched = key.get_key_data();
  size_t key_data_fetched_size = key.get_key_data_size();
  std::string key_data_with_version = "1:" + key_data2;
  EXPECT_STREQ(key_data_with_version.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  EXPECT_STREQ("AES", fetched_key->get_key_type()->c_str());
  ASSERT_TRUE(key_data_with_version.length() + 1 == key_data_fetched_size);

  my_free(fetched_key->release_key_data());

  Key regular_key("Roberts_key4", nullptr, "Robert", nullptr, 0);
  IKey *fetched_regular_key = keys_container->fetch_key(&regular_key);

  ASSERT_TRUE(fetched_regular_key != nullptr);
  std::string expected_regular_key_signature = "Roberts_key4Robert";
  EXPECT_STREQ(fetched_regular_key->get_key_signature()->c_str(),
               expected_regular_key_signature.c_str());
  EXPECT_EQ(fetched_regular_key->get_key_signature()->length(),
            expected_regular_key_signature.length());
  uchar *regular_key_data_fetched = fetched_regular_key->get_key_data();
  size_t regular_key_data_fetched_size =
      fetched_regular_key->get_key_data_size();
  EXPECT_STREQ(key_data4.c_str(),
               reinterpret_cast<const char *>(regular_key_data_fetched));
  ASSERT_TRUE(key_data4.length() + 1 == regular_key_data_fetched_size);

  my_free(fetched_regular_key->release_key_data());
  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_test, StoreFetchSystemKey) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);

  std::string key_data1("system_key_data_1");
  Key *key1 = new Key("percona_binlog:0", "AES", nullptr, key_data1.c_str(),
                      key_data1.length() + 1);

  EXPECT_EQ(keys_container->store_key(key1), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  Key pb_key_verion0("percona_binlog:0", nullptr, nullptr, nullptr, 0);
  IKey *fetched_pb_key_version0 = keys_container->fetch_key(&pb_key_verion0);

  ASSERT_TRUE(fetched_pb_key_version0 != nullptr);
  std::string expected_pb_key_version0_signature = "percona_binlog:0";
  EXPECT_STREQ(fetched_pb_key_version0->get_key_signature()->c_str(),
               expected_pb_key_version0_signature.c_str());
  EXPECT_EQ(fetched_pb_key_version0->get_key_signature()->length(),
            expected_pb_key_version0_signature.length());
  uchar *fetched_pb_key_version0_data_fetched =
      fetched_pb_key_version0->get_key_data();
  size_t fetched_pb_key_data_fetched_size =
      fetched_pb_key_version0->get_key_data_size();
  EXPECT_STREQ(key_data1.c_str(), reinterpret_cast<const char *>(
                                      fetched_pb_key_version0_data_fetched));
  ASSERT_TRUE(key_data1.length() + 1 == fetched_pb_key_data_fetched_size);

  my_free(fetched_pb_key_version0->release_key_data());
  delete sample_key;  // unused in this test
}

// Simulates adding 1 version of percona binlog key
TEST_F(Keys_container_test, StoreWithoutVersionFetchSystemKey) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);

  std::string key_data1("system_key_data_1");
  Key *key1 = new Key("percona_binlog", "AES", nullptr, key_data1.c_str(),
                      key_data1.length() + 1);

  EXPECT_EQ(keys_container->store_key(key1), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  Key pb_key_verion1("percona_binlog:1", nullptr, nullptr, nullptr, 0);
  IKey *fetched_pb_key_version0 = keys_container->fetch_key(&pb_key_verion1);

  ASSERT_TRUE(fetched_pb_key_version1 != nullptr);
  std::string expected_pb_key_version1_signature = "percona_binlog:1";
  EXPECT_STREQ(fetched_pb_key_version1->get_key_signature()->c_str(),
               expected_pb_key_version1_signature.c_str());
  EXPECT_EQ(fetched_pb_key_version1->get_key_signature()->length(),
            expected_pb_key_version1_signature.length());
  uchar *fetched_pb_key_version1_data_fetched =
      fetched_pb_key_version1->get_key_data();
  size_t fetched_pb_key_data_fetched_size =
      fetched_pb_key_version1->get_key_data_size();
  EXPECT_STREQ(key_data1.c_str(), reinterpret_cast<const char *>(
                                      fetched_pb_key_version1_data_fetched));
  ASSERT_TRUE(key_data1.length() + 1 == fetched_pb_key_data_fetched_size);

  my_free(fetched_pb_key_version1->release_key_data());
  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_test, StoreTwiceTheSame) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  EXPECT_EQ(keys_container->store_key(sample_key), 1);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
}

class Buffered_file_io_20 : public Buffered_file_io {
 public:
  Buffered_file_io_20(ILogger *logger) : Buffered_file_io(logger) {}
  void set_memory_needed_for_buffer(size_t memory_needed_for_buffer) {
    this->memory_needed_for_buffer = memory_needed_for_buffer;
  }
};

TEST_F(Keys_container_test, StoreKeyInVer10StoreKeyInVer20FetchKeyInVer20) {
  size_t memory_needed_for_buffer;
  {
    Buffered_file_io_10 keyring_io_10(logger);
    EXPECT_EQ(keys_container->init(&keyring_io_10, file_name), 0);
    EXPECT_EQ(keys_container->store_key(sample_key), 0);
    memory_needed_for_buffer = keyring_io_10.get_memory_needed_for_buffer();
  }
  Buffered_file_io_20 *keyring_io_20 = new Buffered_file_io_20(logger);
  EXPECT_EQ(keyring_io_20->init(&file_name), 0);
  keyring_io_20->set_memory_needed_for_buffer(memory_needed_for_buffer);
  keys_container->set_keyring_io(keyring_io_20);

  std::string key_data1("Robi1");
  Key key_1_id("Roberts_key1", NULL, "Robert", NULL, 0);
  Key *key1 = new Key("Roberts_key1", "AES", "Robert", key_data1.c_str(),
                      key_data1.length() + 1);
  EXPECT_EQ(keys_container->store_key(key1), 0);

  Key key_id("Roberts_key", NULL, "Robert", NULL, 0);
  IKey *fetched_key = keys_container->fetch_key(&key_id);
  ASSERT_TRUE(fetched_key != NULL);
  std::string expected_key_signature = "Roberts_keyRobert";
  EXPECT_STREQ(fetched_key->get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(fetched_key->get_key_signature()->length(),
            expected_key_signature.length());
  uchar *key_data_fetched = fetched_key->get_key_data();
  size_t key_data_fetched_size = fetched_key->get_key_data_size();
  EXPECT_STREQ(sample_key_data.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  ASSERT_TRUE(sample_key_data.length() + 1 == key_data_fetched_size);

  keys_container->remove_key(&key_id);

  IKey *fetched_key_1 = keys_container->fetch_key(&key_1_id);
  ASSERT_TRUE(fetched_key_1 != NULL);
  expected_key_signature = "Roberts_key1Robert";
  EXPECT_STREQ(fetched_key_1->get_key_signature()->c_str(),
               expected_key_signature.c_str());
  EXPECT_EQ(fetched_key_1->get_key_signature()->length(),
            expected_key_signature.length());
  key_data_fetched = fetched_key_1->get_key_data();
  key_data_fetched_size = fetched_key_1->get_key_data_size();
  EXPECT_STREQ(key_data1.c_str(),
               reinterpret_cast<const char *>(key_data_fetched));
  ASSERT_TRUE(key_data1.length() + 1 == key_data_fetched_size);

  keys_container->remove_key(&key_1_id);

  my_free(fetched_key->release_key_data());
  my_free(fetched_key_1->release_key_data());
}

TEST_F(Keys_container_test,
       CheckIfKeyIsNotDumpedIntoKeyringFileIfKeyringFileDoesnotExist) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  remove("./keyring");
  std::string key_data1("Robi1");
  Key *key1 = new Key("Roberts_key1", "AES", "Robert", key_data1.c_str(),
                      key_data1.length() + 1);
  EXPECT_CALL(
      *((Mock_logger *)logger),
      log(ERROR_LEVEL, StrEq("Could not flush keys to keyring's backup")));
  // it should not be possible to store_key if the keyring file does not exist
  EXPECT_EQ(keys_container->store_key(key1), 1);
  delete key1;
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), 0);
}

TEST_F(Keys_container_test,
       CheckIfKeyIsNotDumpedIntoKeyringFileIfKeyringFileHasInvalidDigest) {
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);

  std::fstream keyring_file("./keyring");
  ASSERT_TRUE(keyring_file.is_open());
  keyring_file.seekp(-3, std::ios_base::end);
  keyring_file.write("a", 1);  // changed digest
  keyring_file.close();
  EXPECT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring"));

  std::string key_data1("Robi1");
  Key *key1 = new Key("Roberts_key1", "AES", "Robert", key_data1.c_str(),
                      key_data1.length() + 1);
  EXPECT_CALL(
      *((Mock_logger *)logger),
      log(ERROR_LEVEL, StrEq("Could not flush keys to keyring's backup")));
  EXPECT_CALL(*((Mock_logger *)logger),
              log(ERROR_LEVEL, StrEq("Incorrect Keyring file")));

  // it should not be possible to store_key if the keyring file was changed
  EXPECT_EQ(keys_container->store_key(key1), 1);
  delete key1;
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), true);
}

class Buffered_file_io_dont_remove_backup : public Buffered_file_io {
 public:
  Buffered_file_io_dont_remove_backup(ILogger *logger)
      : Buffered_file_io(logger) {}

  bool remove_backup(myf) { return false; }
};

class Keys_container_test_dont_close : public ::testing::Test {
 public:
  Keys_container_test_dont_close() : file_name("./keyring") {}

 protected:
  virtual void SetUp() {
    sample_key_data = "Robi";
    sample_key = new Key("Roberts_key", "AES", "Robert",
                         sample_key_data.c_str(), sample_key_data.length() + 1);
    std::string sample_key_data2 = "xobi2";
    sample_key2 =
        new Key("Roberts_key2", "AES", "Robert", sample_key_data2.c_str(),
                sample_key_data2.length() + 1);

    // Remove Keyring files just to be save
    remove(file_name.c_str());
    remove("./keyring.backup");
    remove("./keyring.backup.backup");
  }
  virtual void TearDown() { remove(file_name.c_str()); }
  void generate_malformed_keyring_file_without_tag(const char *file_name);

 protected:
  Key *sample_key;
  Key *sample_key2;
  std::string sample_key_data;
  std::string file_name;
};

void Keys_container_test_dont_close::
    generate_malformed_keyring_file_without_tag(const char *file_name) {
  static const char *malformed_keyring_buffer =
      "Key1AESRobertKEYDATA"
      "Key2AESZibiDATAKey3DATA...crashing";

  std::fstream file;
  file.open(file_name,
            std::fstream::out | std::fstream::binary | std::fstream::trunc);
  ASSERT_TRUE(file.is_open());
  file.write(malformed_keyring_buffer, strlen(malformed_keyring_buffer));
  file.close();
}

TEST_F(Keys_container_test_dont_close,
       CheckIfCorrectBackupFileIsCreatedAfterStoringOneKey) {
  ILogger *logger = new Mock_logger();
  IKeyring_io *keyring_io_dont_remove_backup =
      new Buffered_file_io_dont_remove_backup(logger);
  Keys_container *keys_container = new Keys_container(logger);

  EXPECT_EQ(keys_container->init(keyring_io_dont_remove_backup, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), true);

  // Check if backup file is empty
  delete keys_container;
  delete logger;
  logger = new Mock_logger();
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  keys_container = new Keys_container(logger);
  ASSERT_TRUE(keys_container->init(keyring_io, "./keyring.backup") == 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);

  remove("./keyring.backup");
  remove("./keyring.backup.backup");  // leftover from initializing keyring with
                                      // backup file
  remove(file_name.c_str());
  delete keys_container;
  delete logger;
  delete sample_key2;  // unused in this test
}

TEST_F(Keys_container_test_dont_close,
       CheckIfCorrectBackupFileIsCreatedAfterStoringTwoKeys) {
  ILogger *logger = new Mock_logger();
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  Keys_container *keys_container = new Keys_container(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  // successfully stored the key - backup file does not exist
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);
  delete keys_container;
  delete logger;

  logger = new Mock_logger();
  IKeyring_io *keyring_io_dont_remove_backup =
      new Buffered_file_io_dont_remove_backup(logger);
  keys_container = new Keys_container(logger);

  EXPECT_EQ(keys_container->init(keyring_io_dont_remove_backup, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), true);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), true);

  delete keys_container;
  delete logger;
  // Check that backup file contains sample_key only
  logger = new Mock_logger();
  IKeyring_io *keyring_io_2 = new Buffered_file_io(logger);
  keys_container = new Keys_container(logger);
  EXPECT_EQ(keys_container->init(keyring_io_2, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
  IKey *fetchedKey = keys_container->fetch_key(&sample_key_id);
  ASSERT_TRUE(fetchedKey != NULL);

  ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_keyRobert");
  ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "Robi",
                     fetchedKey->get_key_data_size()) == 0);

  remove("./keyring.backup");
  remove("./keyring.backup.backup");  // leftover from initializing keyring with
                                      // backup file
  remove(file_name.c_str());
  delete keys_container;
  delete logger;
  my_free(fetchedKey->release_key_data());
}

TEST_F(Keys_container_test_dont_close,
       CheckIfCorrectBackupFileIsCreatedBeforeRemovingKey) {
  ILogger *logger = new Mock_logger();
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  Keys_container *keys_container = new Keys_container(logger);

  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  // successfully stored the key - backup file does not exist
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);
  EXPECT_EQ(keys_container->store_key(sample_key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);

  delete keys_container;
  delete logger;
  logger = new Mock_logger();
  IKeyring_io *keyring_io_dont_remove_backup =
      new Buffered_file_io_dont_remove_backup(logger);
  keys_container = new Keys_container(logger);

  ASSERT_TRUE(keys_container->init(keyring_io_dont_remove_backup, file_name) ==
              0);
  Key sample_key_id("Roberts_key", "AES", "Robert", NULL, 0);
  EXPECT_EQ(keys_container->remove_key(&sample_key_id), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), true);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), true);

  delete keys_container;
  delete logger;
  // Check that backup file contains sample_key and sample_key2
  logger = new Mock_logger();
  IKeyring_io *keyring_io_2 = new Buffered_file_io(logger);
  keys_container = new Keys_container(logger);
  EXPECT_EQ(keys_container->init(keyring_io_2, "./keyring.backup"), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
  Key sample_key2_id("Roberts_key2", NULL, "Robert", NULL, 0);
  IKey *fetchedKey = keys_container->fetch_key(&sample_key2_id);
  ASSERT_TRUE(fetchedKey != NULL);
  ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_key2Robert");
  ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "xobi2",
                     fetchedKey->get_key_data_size()) == 0);

  remove("./keyring.backup");
  remove("./keyring.backup.backup");  // leftover from initializing keyring with
                                      // backup file
  remove(file_name.c_str());
  delete keys_container;
  delete logger;
  my_free(fetchedKey->release_key_data());
}

TEST_F(Keys_container_test_dont_close,
       CheckIfBackupFileIsNotCreatedForFetching) {
  ILogger *logger = new Mock_logger();
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  Keys_container *keys_container = new Keys_container(logger);

  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  // successfully stored the key - backup file does not exist
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);
  EXPECT_EQ(keys_container->store_key(sample_key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);

  delete keys_container;
  delete logger;
  logger = new Mock_logger();
  IKeyring_io *keyring_io_dont_remove_backup =
      new Buffered_file_io_dont_remove_backup(logger);
  keys_container = new Keys_container(logger);

  EXPECT_EQ(keys_container->init(keyring_io_dont_remove_backup, file_name), 0);
  Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
  IKey *fetchedKey = keys_container->fetch_key(&sample_key_id);
  ASSERT_TRUE(fetchedKey != NULL);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
  // check if the backup file was not created
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), true);

  remove("./keyring.backup");
  remove(file_name.c_str());
  delete keys_container;
  delete logger;
  my_free(fetchedKey->release_key_data());
}

TEST_F(Keys_container_test_dont_close,
       KeyringfileIsMalformedCheckIfBackupIsLoaded) {
  ILogger *logger = new Mock_logger();
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  Keys_container *keys_container = new Keys_container(logger);

  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  // successfully stored the key - backup file does not exist
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);
  EXPECT_EQ(keys_container->store_key(sample_key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
  // Now we have correct backup file
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);

  delete keys_container;
  delete logger;
  logger = new Mock_logger();
  IKeyring_io *keyring_io_dont_remove_backup =
      new Buffered_file_io_dont_remove_backup(logger);
  keys_container = new Keys_container(logger);

  // this key will not be in backup file thus we do not care about it
  Key *sample_key3 = new Key("Roberts_key3", "ZZZZ", "MaybeRobert",
                             (void *)("DATA"), strlen("DATA"));

  EXPECT_EQ(keys_container->init(keyring_io_dont_remove_backup, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key3), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 3);
  // Now we have correct backup file
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), true);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);

  delete keys_container;
  delete logger;
  remove("./keyring");
  generate_malformed_keyring_file_without_tag("./keyring");
  logger = new Mock_logger();
  IKeyring_io *keyring_io_2 = new Buffered_file_io(logger);
  keys_container = new Keys_container(logger);

  ASSERT_TRUE(keys_container->init(keyring_io_2, file_name) == 0);
  // Check that keyring from backup was loaded as the keyring file is corrupted
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
  Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
  Key sample_key2_id("Roberts_key2", NULL, "Robert", NULL, 0);
  IKey *fetchedKey = keys_container->fetch_key(&sample_key2_id);
  ASSERT_TRUE(fetchedKey != NULL);
  ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_key2Robert");
  ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "xobi2",
                     fetchedKey->get_key_data_size()) == 0);
  IKey *fetchedKey2 = keys_container->fetch_key(&sample_key_id);
  ASSERT_TRUE(fetchedKey2 != NULL);
  ASSERT_TRUE(*fetchedKey2->get_key_signature() == "Roberts_keyRobert");
  ASSERT_TRUE(memcmp(fetchedKey2->get_key_data(), "Robi",
                     fetchedKey2->get_key_data_size()) == 0);

  // check if the backup file was removed
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), true);

  remove("./keyring.backup");
  remove(file_name.c_str());
  delete keys_container;
  delete logger;
  my_free(fetchedKey->release_key_data());
  my_free(fetchedKey2->release_key_data());
}

TEST_F(Keys_container_test_dont_close,
       BackupfileIsMalformedCheckItIsIgnoredAndDeleted) {
  ILogger *logger = new Mock_logger();
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  Keys_container *keys_container = new Keys_container(logger);

  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  // successfully stored the key - backup file does not exist
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);
  EXPECT_EQ(keys_container->store_key(sample_key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);

  delete keys_container;
  delete logger;
  generate_malformed_keyring_file_without_tag("./keyring.backup");
  logger = new Mock_logger();
  IKeyring_io *keyring_io_2 = new Buffered_file_io(logger);
  keys_container = new Keys_container(logger);

  // Check that backup file was ignored (as backup file is malformed)
  EXPECT_CALL(*((Mock_logger *)logger),
              log(ERROR_LEVEL, StrEq("Incorrect Keyring file")));
  EXPECT_CALL(*((Mock_logger *)logger),
              log(WARNING_LEVEL,
                  StrEq("Found malformed keyring backup file - removing it")));
  EXPECT_EQ(keys_container->init(keyring_io_2, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);
  Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
  Key sample_key2_id("Roberts_key2", NULL, "Robert", NULL, 0);
  IKey *fetchedKey = keys_container->fetch_key(&sample_key2_id);
  ASSERT_TRUE(fetchedKey != NULL);
  ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_key2Robert");
  ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "xobi2",
                     fetchedKey->get_key_data_size()) == 0);
  IKey *fetchedKey2 = keys_container->fetch_key(&sample_key_id);
  ASSERT_TRUE(fetchedKey2 != NULL);
  ASSERT_TRUE(*fetchedKey2->get_key_signature() == "Roberts_keyRobert");
  ASSERT_TRUE(memcmp(fetchedKey2->get_key_data(), "Robi",
                     fetchedKey2->get_key_data_size()) == 0);

  // check if the backup file was removed
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), false);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), true);

  delete keys_container;
  delete logger;
  my_free(fetchedKey->release_key_data());
  my_free(fetchedKey2->release_key_data());
}

TEST_F(
    Keys_container_test_dont_close,
    CheckIfBackupIsCreatedAfterEachOperationAndIsUsedWhenKeyringDoesNotExist) {
  ILogger *logger = new Mock_logger();
  IKeyring_io *keyring_io = new Buffered_file_io_dont_remove_backup(logger);
  Keys_container *keys_container = new Keys_container(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), true);
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == true);

  remove("./keyring.backup");
  rename("keyring", "keyring.backup");
  ASSERT_TRUE(check_if_file_exists_and_TAG_is_correct("./keyring") == false);
  // Now keyring file should be recreated based on keyring.backup
  delete keys_container;
  keyring_io = new Buffered_file_io_dont_remove_backup(logger);
  keys_container = new Keys_container(logger);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);

  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);
  EXPECT_EQ(keys_container->store_key(sample_key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring.backup"), true);
  EXPECT_EQ(check_if_file_exists_and_TAG_is_correct("./keyring"), true);

  Key sample_key_id("Roberts_key", NULL, "Robert", NULL, 0);
  IKey *fetchedKey = keys_container->fetch_key(&sample_key_id);
  ASSERT_TRUE(fetchedKey != NULL);

  ASSERT_TRUE(*fetchedKey->get_key_signature() == "Roberts_keyRobert");
  ASSERT_TRUE(memcmp(fetchedKey->get_key_data(), "Robi",
                     fetchedKey->get_key_data_size()) == 0);

  remove("./keyring.backup");
  remove(file_name.c_str());
  delete keys_container;
  delete logger;
  my_free(fetchedKey->release_key_data());
  //    fetchedKey->release_key_data();
}

class Mock_keyring_io : public IKeyring_io {
 public:
  MOCK_METHOD1(init, bool(std::string *keyring_filename));
  MOCK_METHOD1(flush_to_backup, bool(ISerialized_object *serialized_object));
  MOCK_METHOD1(flush_to_storage, bool(ISerialized_object *serialized_object));
  MOCK_METHOD0(get_serializer, ISerializer *());
  MOCK_METHOD1(get_serialized_object,
               bool(ISerialized_object **serialized_object));
  MOCK_METHOD0(has_next_serialized_object, bool());
};

class Mock_serialized_object : public ISerialized_object {
 public:
  MOCK_METHOD1(get_next_key, bool(IKey **key));
  MOCK_METHOD0(has_next_key, bool());
  MOCK_METHOD0(get_key_operation, Key_operation());
  MOCK_METHOD1(set_key_operation, void(Key_operation));
};

class Mock_serializer : public ISerializer {
 public:
  MOCK_METHOD3(
      serialize,
      ISerialized_object *(
          const collation_unordered_map<std::string, std::unique_ptr<IKey>> &,
          IKey *, Key_operation));
};

class Keys_container_with_mocked_io_test : public ::testing::Test {
 protected:
  virtual void SetUp() {
    std::string sample_key_data("Robi");
    sample_key = new Key("Roberts_key", "AES", "Robert",
                         sample_key_data.c_str(), sample_key_data.length() + 1);

    file_name = "/home/rob/write_key";
  }
  virtual void TearDown() {
    remove(file_name.c_str());
    delete keys_container;
  }

 protected:
  Keys_container *keys_container;
  Mock_keyring_io *keyring_io;
  Key *sample_key;
  char *sample_key_data;
  std::string file_name;

  void expect_calls_on_init();
  void expect_calls_on_store_sample_key();
};

void Keys_container_with_mocked_io_test::expect_calls_on_init() {
  Mock_serialized_object *mock_serialized_object = new Mock_serialized_object;

  EXPECT_CALL(*keyring_io, init(Pointee(StrEq(file_name))))
      .WillOnce(Return(0));  // init successfull
  EXPECT_CALL(*keyring_io, get_serialized_object(_))
      .WillOnce(DoAll(SetArgPointee<0>(mock_serialized_object), Return(false)));
  EXPECT_CALL(*mock_serialized_object, has_next_key())
      .WillOnce(Return(false));  // no keys to read
  EXPECT_CALL(*keyring_io, has_next_serialized_object())
      .WillOnce(Return(false));
}

TEST_F(Keys_container_with_mocked_io_test,
       ErrorFromIODuringInitOnGettingSerializedObject) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);

  EXPECT_CALL(*keyring_io, init(Pointee(StrEq(file_name))))
      .WillOnce(Return(0));  // init successfull
  EXPECT_CALL(*keyring_io, get_serialized_object(_)).WillOnce(Return(true));
  EXPECT_CALL(*logger,
              log(ERROR_LEVEL, StrEq("Error while loading keyring content. The "
                                     "keyring might be malformed")));

  EXPECT_EQ(keys_container->init(keyring_io, file_name), 1);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  delete logger;
  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_with_mocked_io_test,
       ErrorFromIODuringInitInvalidKeyAndMockedSerializedObject) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);

  IKey *invalid_key = new Key();
  std::string invalid_key_type("ZZZ");
  invalid_key->set_key_type(&invalid_key_type);

  Mock_serialized_object *mock_serialized_object = new Mock_serialized_object;

  EXPECT_CALL(*keyring_io, init(Pointee(StrEq(file_name))))
      .WillOnce(Return(0));  // init successfull
  {
    InSequence dummy;
    EXPECT_CALL(*keyring_io, get_serialized_object(_))
        .WillOnce(
            DoAll(SetArgPointee<0>(mock_serialized_object), Return(false)));
    EXPECT_CALL(*mock_serialized_object, has_next_key()).WillOnce(Return(true));
    EXPECT_CALL(*mock_serialized_object, get_next_key(_))
        .WillOnce(DoAll(SetArgPointee<0>(sample_key), Return(false)));
    EXPECT_CALL(*mock_serialized_object, has_next_key()).WillOnce(Return(true));
    EXPECT_CALL(*mock_serialized_object, get_next_key(_))
        .WillOnce(DoAll(SetArgPointee<0>(invalid_key), Return(false)));

    EXPECT_CALL(*logger,
                log(ERROR_LEVEL, StrEq("Error while loading keyring content. "
                                       "The keyring might be malformed")));
  }

  EXPECT_EQ(keys_container->init(keyring_io, file_name), 1);
  ASSERT_EQ(0u, keys_container->get_number_of_keys());
  delete logger;
}

TEST_F(Keys_container_with_mocked_io_test, ErrorFromIODuringInitInvalidKey) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);

  IKey *invalid_key = new Key();
  std::string invalid_key_type("ZZZ");
  invalid_key->set_key_type(&invalid_key_type);

  Buffer *buffer = new Buffer(sample_key->get_key_pod_size() +
                              invalid_key->get_key_pod_size());
  sample_key->store_in_buffer(buffer->data, &(buffer->position));
  invalid_key->store_in_buffer(buffer->data, &(buffer->position));
  buffer->position = 0;  // rewind buffer

  EXPECT_CALL(*keyring_io, init(Pointee(StrEq(file_name))))
      .WillOnce(Return(0));  // init successfull
  {
    InSequence dummy;
    EXPECT_CALL(*keyring_io, get_serialized_object(_))
        .WillOnce(DoAll(SetArgPointee<0>(buffer), Return(false)));
    EXPECT_CALL(*logger,
                log(ERROR_LEVEL, StrEq("Error while loading keyring content. "
                                       "The keyring might be malformed")));
  }
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 1);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  delete logger;
  delete invalid_key;
  delete sample_key;  // unused in this test
}

TEST_F(Keys_container_with_mocked_io_test,
       ErrorFromSerializerOnFlushToBackupWhenStoringKey) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);
  expect_calls_on_init();
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  Mock_serializer *mock_serializer = new Mock_serializer;

  {
    InSequence dummy;

    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return((ISerialized_object *)NULL));
    EXPECT_CALL(
        *logger,
        log(ERROR_LEVEL, StrEq("Could not flush keys to keyring's backup")));
  }
  EXPECT_EQ(keys_container->store_key(sample_key), 1);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);

  delete logger;
  delete sample_key;
  delete mock_serializer;
}

TEST_F(Keys_container_with_mocked_io_test,
       ErrorFromSerializerOnFlushToKeyringWhenStoringKey) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);
  expect_calls_on_init();
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  Mock_serializer *mock_serializer = new Mock_serializer;

  ISerialized_object *empty_serialized_object = new Buffer;

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(empty_serialized_object));
    EXPECT_CALL(*keyring_io, flush_to_backup(empty_serialized_object));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, STORE_KEY))
        .WillOnce(Return((ISerialized_object *)NULL));
    EXPECT_CALL(*logger,
                log(ERROR_LEVEL, StrEq("Could not flush keys to keyring")));
  }
  EXPECT_EQ(keys_container->store_key(sample_key), 1);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);

  delete logger;
  delete sample_key;
  delete mock_serializer;
}

TEST_F(Keys_container_with_mocked_io_test,
       ErrorFromSerializerOnFlushToBackupWhenRemovingKey) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);
  expect_calls_on_init();
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  Mock_serializer *mock_serializer = new Mock_serializer;

  ISerialized_object *empty_serialized_object = new Buffer;
  Buffer *serialized_object_with_sample_key =
      new Buffer(sample_key->get_key_pod_size());
  sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                              &(serialized_object_with_sample_key->position));
  serialized_object_with_sample_key->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(empty_serialized_object));
    EXPECT_CALL(*keyring_io, flush_to_backup(empty_serialized_object));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, STORE_KEY))
        .WillOnce(Return(serialized_object_with_sample_key));
    EXPECT_CALL(*keyring_io,
                flush_to_storage(serialized_object_with_sample_key));
  }
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  {
    InSequence dummy;

    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return((ISerialized_object *)NULL));
    EXPECT_CALL(
        *logger,
        log(ERROR_LEVEL, StrEq("Could not flush keys to keyring's backup")));
  }
  EXPECT_EQ(keys_container->remove_key(sample_key), 1);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  delete logger;
  delete mock_serializer;
}

TEST_F(Keys_container_with_mocked_io_test,
       ErrorFromSerializerOnFlushToKeyringWhenRemovingKey) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);
  expect_calls_on_init();
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  Mock_serializer *mock_serializer = new Mock_serializer;

  ISerialized_object *empty_serialized_object = new Buffer;
  Buffer *serialized_object_with_sample_key =
      new Buffer(sample_key->get_key_pod_size());
  sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                              &(serialized_object_with_sample_key->position));
  serialized_object_with_sample_key->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(empty_serialized_object));
    EXPECT_CALL(*keyring_io, flush_to_backup(empty_serialized_object));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, STORE_KEY))
        .WillOnce(Return(serialized_object_with_sample_key));
    EXPECT_CALL(*keyring_io,
                flush_to_storage(serialized_object_with_sample_key));
  }
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  serialized_object_with_sample_key =
      new Buffer(sample_key->get_key_pod_size());
  sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                              &(serialized_object_with_sample_key->position));
  serialized_object_with_sample_key->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(serialized_object_with_sample_key));
    EXPECT_CALL(*keyring_io,
                flush_to_backup(serialized_object_with_sample_key));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, REMOVE_KEY))
        .WillOnce(Return((ISerialized_object *)NULL));
    EXPECT_CALL(*logger,
                log(ERROR_LEVEL, StrEq("Could not flush keys to keyring")));
  }

  EXPECT_EQ(keys_container->remove_key(sample_key), 1);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  delete logger;
  delete mock_serializer;
}

TEST_F(Keys_container_with_mocked_io_test, StoreAndRemoveKey) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);
  expect_calls_on_init();
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  Mock_serializer *mock_serializer = new Mock_serializer;

  ISerialized_object *empty_serialized_object = new Buffer;
  Buffer *serialized_object_with_sample_key =
      new Buffer(sample_key->get_key_pod_size());
  sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                              &(serialized_object_with_sample_key->position));
  serialized_object_with_sample_key->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(empty_serialized_object));
    EXPECT_CALL(*keyring_io, flush_to_backup(empty_serialized_object));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, STORE_KEY))
        .WillOnce(Return(serialized_object_with_sample_key));
    EXPECT_CALL(*keyring_io,
                flush_to_storage(serialized_object_with_sample_key));
  }
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  // recreate serialized objects
  empty_serialized_object = new Buffer;

  serialized_object_with_sample_key =
      new Buffer(sample_key->get_key_pod_size());
  sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                              &(serialized_object_with_sample_key->position));
  serialized_object_with_sample_key->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(serialized_object_with_sample_key));
    EXPECT_CALL(*keyring_io,
                flush_to_backup(serialized_object_with_sample_key));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, REMOVE_KEY))
        .WillOnce(Return(empty_serialized_object));
    EXPECT_CALL(*keyring_io, flush_to_storage(empty_serialized_object));
  }

  EXPECT_EQ(keys_container->remove_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);

  delete logger;
  delete mock_serializer;
}

TEST_F(Keys_container_with_mocked_io_test,
       ErrorFromIOWhileRemovingKeyAfterAdding2Keys) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);
  expect_calls_on_init();
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  Mock_serializer *mock_serializer = new Mock_serializer;

  ISerialized_object *empty_serialized_object = new Buffer;
  Buffer *serialized_object_with_sample_key =
      new Buffer(sample_key->get_key_pod_size());
  sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                              &(serialized_object_with_sample_key->position));
  serialized_object_with_sample_key->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(empty_serialized_object));
    EXPECT_CALL(*keyring_io, flush_to_backup(empty_serialized_object));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, STORE_KEY))
        .WillOnce(Return(serialized_object_with_sample_key));
    EXPECT_CALL(*keyring_io,
                flush_to_storage(serialized_object_with_sample_key));
  }
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  std::string key_data2("Robi2");
  Key *key2 = new Key("Roberts_key2", "AES", "Robert", key_data2.c_str(),
                      key_data2.length() + 1);

  serialized_object_with_sample_key =
      new Buffer(sample_key->get_key_pod_size());
  sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                              &(serialized_object_with_sample_key->position));
  serialized_object_with_sample_key->position = 0;  // rewind buffer

  Buffer *serialized_object_with_sample_key_and_key2 =
      new Buffer(sample_key->get_key_pod_size() + key2->get_key_pod_size());
  sample_key->store_in_buffer(
      serialized_object_with_sample_key_and_key2->data,
      &(serialized_object_with_sample_key_and_key2->position));
  key2->store_in_buffer(
      serialized_object_with_sample_key_and_key2->data,
      &(serialized_object_with_sample_key_and_key2->position));
  serialized_object_with_sample_key_and_key2->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(serialized_object_with_sample_key));
    EXPECT_CALL(*keyring_io,
                flush_to_backup(serialized_object_with_sample_key));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, key2, STORE_KEY))
        .WillOnce(Return(serialized_object_with_sample_key_and_key2));
    EXPECT_CALL(*keyring_io,
                flush_to_storage(serialized_object_with_sample_key_and_key2));
  }
  EXPECT_EQ(keys_container->store_key(key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  serialized_object_with_sample_key_and_key2 =
      new Buffer(sample_key->get_key_pod_size() + key2->get_key_pod_size());
  sample_key->store_in_buffer(
      serialized_object_with_sample_key_and_key2->data,
      &(serialized_object_with_sample_key_and_key2->position));
  key2->store_in_buffer(
      serialized_object_with_sample_key_and_key2->data,
      &(serialized_object_with_sample_key_and_key2->position));
  serialized_object_with_sample_key_and_key2->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(serialized_object_with_sample_key_and_key2));
    EXPECT_CALL(*keyring_io,
                flush_to_backup(serialized_object_with_sample_key_and_key2));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, REMOVE_KEY))
        .WillOnce(Return((ISerialized_object *)NULL));
    EXPECT_CALL(*logger,
                log(ERROR_LEVEL, StrEq("Could not flush keys to keyring")));
  }

  EXPECT_EQ(keys_container->remove_key(sample_key), 1);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  delete logger;
  delete mock_serializer;
}

TEST_F(Keys_container_with_mocked_io_test, Store2KeysAndRemoveThem) {
  keyring_io = new Mock_keyring_io();
  Mock_logger *logger = new Mock_logger();
  keys_container = new Keys_container(logger);
  expect_calls_on_init();
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);
  Mock_serializer *mock_serializer = new Mock_serializer;

  ISerialized_object *empty_serialized_object = new Buffer;
  Buffer *serialized_object_with_sample_key =
      new Buffer(sample_key->get_key_pod_size());
  sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                              &(serialized_object_with_sample_key->position));
  serialized_object_with_sample_key->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(empty_serialized_object));
    EXPECT_CALL(*keyring_io, flush_to_backup(empty_serialized_object));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, STORE_KEY))
        .WillOnce(Return(serialized_object_with_sample_key));
    EXPECT_CALL(*keyring_io,
                flush_to_storage(serialized_object_with_sample_key));
  }
  EXPECT_EQ(keys_container->store_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  std::string key_data2("Robi2");
  Key *key2 = new Key("Roberts_key2", "AES", "Robert", key_data2.c_str(),
                      key_data2.length() + 1);

  serialized_object_with_sample_key =
      new Buffer(sample_key->get_key_pod_size());
  sample_key->store_in_buffer(serialized_object_with_sample_key->data,
                              &(serialized_object_with_sample_key->position));
  serialized_object_with_sample_key->position = 0;  // rewind buffer

  Buffer *serialized_object_with_sample_key_and_key2 =
      new Buffer(sample_key->get_key_pod_size() + key2->get_key_pod_size());
  sample_key->store_in_buffer(
      serialized_object_with_sample_key_and_key2->data,
      &(serialized_object_with_sample_key_and_key2->position));
  key2->store_in_buffer(
      serialized_object_with_sample_key_and_key2->data,
      &(serialized_object_with_sample_key_and_key2->position));
  serialized_object_with_sample_key_and_key2->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(serialized_object_with_sample_key));
    EXPECT_CALL(*keyring_io,
                flush_to_backup(serialized_object_with_sample_key));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, key2, STORE_KEY))
        .WillOnce(Return(serialized_object_with_sample_key_and_key2));
    EXPECT_CALL(*keyring_io,
                flush_to_storage(serialized_object_with_sample_key_and_key2));
  }
  EXPECT_EQ(keys_container->store_key(key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 2);

  serialized_object_with_sample_key_and_key2 =
      new Buffer(sample_key->get_key_pod_size() + key2->get_key_pod_size());
  sample_key->store_in_buffer(
      serialized_object_with_sample_key_and_key2->data,
      &(serialized_object_with_sample_key_and_key2->position));
  key2->store_in_buffer(
      serialized_object_with_sample_key_and_key2->data,
      &(serialized_object_with_sample_key_and_key2->position));
  serialized_object_with_sample_key_and_key2->position = 0;  // rewind buffer

  Buffer *serialized_object_with_key2 = new Buffer(key2->get_key_pod_size());
  key2->store_in_buffer(serialized_object_with_key2->data,
                        &(serialized_object_with_key2->position));
  serialized_object_with_key2->position = 0;  // rewind buffer

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(serialized_object_with_sample_key_and_key2));
    EXPECT_CALL(*keyring_io,
                flush_to_backup(serialized_object_with_sample_key_and_key2));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, sample_key, REMOVE_KEY))
        .WillOnce(Return(serialized_object_with_key2));
    EXPECT_CALL(*keyring_io, flush_to_storage(serialized_object_with_key2));
  }

  EXPECT_EQ(keys_container->remove_key(sample_key), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 1);

  serialized_object_with_key2 = new Buffer(key2->get_key_pod_size());
  key2->store_in_buffer(serialized_object_with_key2->data,
                        &(serialized_object_with_key2->position));
  serialized_object_with_key2->position = 0;  // rewind buffer

  empty_serialized_object = new Buffer;

  {
    InSequence dummy;
    // flush to backup
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, NULL, NONE))
        .WillOnce(Return(serialized_object_with_key2));
    EXPECT_CALL(*keyring_io, flush_to_backup(serialized_object_with_key2));
    // flush to keyring
    EXPECT_CALL(*keyring_io, get_serializer())
        .WillOnce(Return(mock_serializer));
    EXPECT_CALL(*mock_serializer, serialize(_, key2, REMOVE_KEY))
        .WillOnce(Return(empty_serialized_object));
    EXPECT_CALL(*keyring_io, flush_to_storage(empty_serialized_object));
  }

  EXPECT_EQ(keys_container->remove_key(key2), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);

  delete logger;
  delete mock_serializer;
}

class Mock_system_keys_container : public ISystem_keys_container {
 public:
  MOCK_METHOD1(get_latest_key_if_system_key_without_version, IKey *(IKey *key));
  MOCK_METHOD1(store_or_update_if_system_key_with_version, void(IKey *key));
  MOCK_METHOD1(rotate_key_id_if_system_key_without_version, bool(IKey *key));
  MOCK_METHOD1(is_system_key, bool(IKey *key));
};

class Keys_container_with_system_keys_container_setter : public Keys_container {
 public:
  Keys_container_with_system_keys_container_setter(ILogger *logger)
      : Keys_container(logger) {}
  void set_system_keys_container(
      ISystem_keys_container *system_keys_container) {
    this->system_keys_container.reset(system_keys_container);
  }
};

class Keys_container_with_mocked_system_keys_container_test
    : public ::testing::Test {
 protected:
  virtual void SetUp() {
    std::string sample_key_data("Robi");
    sample_key = new Key("Roberts_key", "AES", "Robert",
                         sample_key_data.c_str(), sample_key_data.length() + 1);

    file_name = "./write_key";
  }
  virtual void TearDown() { remove(file_name.c_str()); }

 protected:
  Key *sample_key;
  char *sample_key_data;
  std::string file_name;
};

TEST_F(Keys_container_with_mocked_system_keys_container_test,
       ErrorFromRotateKeyWhenStoringKey) {
  Mock_logger *logger = new Mock_logger();
  Keys_container_with_system_keys_container_setter *keys_container =
      new Keys_container_with_system_keys_container_setter(logger);
  IKeyring_io *keyring_io = new Buffered_file_io(logger);
  Mock_system_keys_container *system_keys_container =
      new Mock_system_keys_container;
  keys_container->set_system_keys_container(system_keys_container);
  EXPECT_EQ(keys_container->init(keyring_io, file_name), 0);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);

  EXPECT_CALL(*system_keys_container,
              rotate_key_id_if_system_key_without_version(sample_key))
      .WillOnce(Return(true));  // error on key rotation
  EXPECT_EQ(keys_container->store_key(sample_key), 1);
  ASSERT_TRUE(keys_container->get_number_of_keys() == 0);

  delete logger;
  delete sample_key;
  delete keys_container;
}

int main(int argc, char **argv) {
  if (mysql_rwlock_init(key_LOCK_keyring, &LOCK_keyring)) return true;
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
}  // namespace keyring__keys_container_unittest
