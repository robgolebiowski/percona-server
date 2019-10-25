--source include/have_keyring_vault_plugin.inc
--source include/not_repeat.inc
--source generate_default_directory_conf_files.inc
--source is_vault_server_up.inc

--let $keyring_restart_param=restart:--early-plugin-load="keyring_vault=$KEYRING_VAULT_PLUGIN" --loose-keyring_vault_config=$KEYRING_CONF_FILE_2 $KEYRING_VAULT_PLUGIN_OPT
--source include/table_encrypt_4.inc

# Remove all secrets in directories used by this test. When all secrets are removed from directory
# in Vault Server, the directory is removed automatically. 
--let $KEYRING_CONF_FILE=$KEYRING_CONF_FILE_2
--source vault_cleanup.inc
