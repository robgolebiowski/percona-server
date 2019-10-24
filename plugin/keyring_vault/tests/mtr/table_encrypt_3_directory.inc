--source include/big_test.inc
--source include/have_keyring_vault_plugin.inc
--source include/not_repeat.inc

--source generate_default_directory_conf_files.inc
--source is_vault_server_up.inc

--let $keyring_plugin_name=keyring_vault
--let $keyring_restart_param=restart: --early-plugin-load="keyring_vault=$KEYRING_VAULT_PLUGIN" --loose-keyring_vault_config=$KEYRING_CONF_FILE_1 $KEYRING_VAULT_PLUGIN_OPT

--let $number_of_MK_rotations=100
--source include/table_encrypt_3.inc

