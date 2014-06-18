var config = {};

config.account_host = 'https://account.lab.fi-ware.org';

config.keystone_host = 'cloud.lab.fi-ware.org';
config.keystone_port = 4731;

config.app_host = 'www.google.es';
config.app_port = '80';

config.username = 'pepProxy';
config.password = 'pepProxy';

config.idm_role_regexp = '^\.*-(\.*)$';

config.check_roles_services = true;

config.privileged_roles = ['adminprovider'];

module.exports = config;
