--let $KEYRING_CONF_FILE_1=$MYSQLTEST_VARDIR/std_data/keyring_vault_confs/keyring_vault1.conf
--let $KEYRING_CONF_FILE_2=$MYSQLTEST_VARDIR/std_data/keyring_vault_confs/keyring_vault2.conf
--let $KEYRING_INVALID_TOKEN_CONF_FILE=$MYSQLTEST_VARDIR/keyring_vault_invalid_token.conf

if ($USE_KV_V1_WITH_SECRET_VERSION_SET_TO_1) {
--echo # Using configuration file with secret_mount_point_version set to 1

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_mount_template1_v1_set.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_1
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_mount_template2_v1_set.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_2
--source generate_conf_file.inc
}

if ($USE_KV_V2_WITH_SECRET_VERSION_SET_TO_2) {
--echo # Using configuration file with secret_mount_point_version set to 2

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_mount_template1_v2_set.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_1
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_mount_template2_v2_set.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_2
--source generate_conf_file.inc
}

# For USE_KV_V1 and USE_KV_V2 we are using the same configuration files. However, since MTR does not undersntand AND
# I need to repeat the same code for USE_KV_V2
if ($USE_KV_V1) {
--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_mount_template1.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_1
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_mount_template2.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_2
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_invalid_token_template.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_INVALID_TOKEN_CONF_FILE
--source generate_conf_file.inc
}

if ($USE_KV_V2) {
--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_mount_template1.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_1
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_mount_template2.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_CONF_FILE_2
--source generate_conf_file.inc

--let $KEYRING_CONF_TEMPLATE_FILE=$MYSQL_TEST_DIR/std_data/keyring_vault_confs/keyring_vault_mtr_invalid_token_template.conf
--let $KEYRING_CONF_FILE_TO_GENERATE=$KEYRING_INVALID_TOKEN_CONF_FILE
--source generate_conf_file.inc
}
