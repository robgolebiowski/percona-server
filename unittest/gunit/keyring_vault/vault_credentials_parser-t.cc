//
// Created by rob on 08.03.17.
//
#include <my_global.h>
#include <gtest/gtest.h>
#include "mock_logger.h"
#include "vault_credentials_parser.h"
#include <fstream>

#if defined(HAVE_PSI_INTERFACE)
namespace keyring
{
  PSI_memory_key key_memory_KEYRING = PSI_NOT_INSTRUMENTED;
//  PSI_memory_key key_LOCK_keyring = PSI_NOT_INSTRUMENTED;
}
#endif

namespace keyring__vault_credentials_parser_unittest
{
  using namespace keyring;

  using ::testing::StrEq;

  class Vault_credentials_parser_test : public ::testing::Test
  {
  protected:
    virtual void SetUp()
    {
//      keyring_file_data_key = PSI_NOT_INSTRUMENTED;
//      keyring_backup_file_data_key = PSI_NOT_INSTRUMENTED;
      logger= new Mock_logger();
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

  TEST_F(Vault_credentials_parser_test, ParseNotExistingFile)
  {
    Vault_credentials_parser vault_credentials_parser(logger);
    std::string token;

    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not open file with credentials.")));
    std::string file_url = "/.there_no_such_file";
    Vault_credentials vault_credentials;
    EXPECT_EQ(vault_credentials_parser.parse(&file_url, &vault_credentials), TRUE);
    EXPECT_EQ(vault_credentials["vault_url"].empty(), TRUE);
    EXPECT_EQ(vault_credentials["token"].empty(), TRUE);
    EXPECT_EQ(vault_credentials["secret_mount_point"].empty(), TRUE);

    ASSERT_TRUE(token.empty());
  }

  TEST_F(Vault_credentials_parser_test, ParseEmptyFile)
  {
    Vault_credentials_parser vault_credentials_parser(logger);
    std::string token;

    //create empty credentials file
    std::remove("./credentials");
    std::ofstream myfile;
    myfile.open("./credentials");
    myfile.close();

    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not read secret_mount_point from the configuration file.")));
    std::string file_url = "./credentials";

    Vault_credentials vault_credentials;
    EXPECT_EQ(vault_credentials_parser.parse(&file_url, &vault_credentials), TRUE);
    EXPECT_EQ(vault_credentials["vault_url"].empty(), TRUE);
    EXPECT_EQ(vault_credentials["token"].empty(), TRUE);
    EXPECT_EQ(vault_credentials["secret_mount_point"].empty(), TRUE);
    std::remove("./credentials");
  }
/*
  TEST_F(Vault_credentials_parser_test, ParseFileWithTokenWithSpaceInIt)
  {
    Vault_credentials_parser vault_credentials(logger);
    std::string token;
    std::string file_url = "./credentials";

    //create empty credentials file
    std::remove(file_url.c_str());
    std::ofstream myfile;
    myfile.open(file_url.c_str());
    myfile << "token ups";
    myfile.close();

    EXPECT_CALL(*((Mock_logger *)logger),
      log(MY_ERROR_LEVEL, StrEq("Could not read token from credential file.")));
    EXPECT_EQ(vault_credentials.parse(&file_url, &token), TRUE);
    ASSERT_TRUE(token.empty());
    std::remove(file_url.c_str());
  }

  TEST_F(Vault_credentials_parser_test, ParseCredentialFileWithOneToken)
  {
    Vault_credentials_parser vault_credentials(logger);
    std::string token;
    std::string token_in_file("123-Token_here-321");
    std::string file_url = "./credentials";

    std::remove(file_url.c_str());
    std::ofstream myfile;
    myfile.open(file_url.c_str());
    myfile << token_in_file;
    myfile.close();

    EXPECT_EQ(vault_credentials.parse(&file_url, &token), FALSE);
    EXPECT_STREQ(token.c_str(), token_in_file.c_str());
    std::remove(file_url.c_str());
  }*/
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}














































