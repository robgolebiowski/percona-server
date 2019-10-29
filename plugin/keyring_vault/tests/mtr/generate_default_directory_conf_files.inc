--let $KEYRING_CONF_FILE_1=$MYSQLTEST_VARDIR/std_data/keyring_vault_confs/keyring_vault1.conf
--let $KEYRING_CONF_FILE_2=$MYSQLTEST_VARDIR/std_data/keyring_vault_confs/keyring_vault2.conf
--let $KEYRING_INVALID_TOKEN_CONF_FILE=$MYSQLTEST_VARDIR/keyring_vault_invalid_token.conf

if ($USE_KV_V2) {
--echo # Using kv v2
--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_v2_mtr_directory_template1.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_1
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_v2_mtr_directory_template2.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_2
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_v2_mtr_invalid_token_template.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_INVALID_TOKEN_CONF_FILE
--source generate_conf_file.inc
}
if ($USE_KV_V1) {
--echo # Using kv v1
--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_directory_template1.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_1
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_directory_template2.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_2
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_invalid_token_template.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_INVALID_TOKEN_CONF_FILE
--source generate_conf_file.inc
}
if ($USE_KV_V1_WITH_SECRET_VERSION_SET_TO_1) {
--echo # Using configuration file with secret_mount_point_version set to 1
--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_directory_template1_v1_set.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_1
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_directory_template2_v1_set.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_2
--source generate_conf_file.inc
}
if ($USE_KV_V2_WITH_SECRET_VERSION_SET_TO_2) {
--echo # Using configuration file with secret_mount_point_version set to 2

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_v2_mtr_directory_template1_v2_set.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_1
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_v2_mtr_directory_template2_v2_set.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_2
--source generate_conf_file.inc
}
