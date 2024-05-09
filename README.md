# Roundcube Plugin restrict_user_access

Roundcube plugin to allow login from restricted networks. Certain users can also be granted all access.

# Installation

1. download restrict_user_access.tar.gz
2. extract tar.gz to plugin dir

# Settings
Plugin params.

```
# IPv4 networks to allow connections
$config['allowed_ipv4_networks'] = ['127.0.0.1', '192.168.0.0/16'];

# IPv6 networks to allow connections
$config['allowed_ipv6_networks'] = [];

# User ID that allows all connections.
# Register the user ID used for IMAP login.
# In cases where authentication can be performed using both an email address and local part,
# it is necessary to register both IDs.
$config['whitelist_users'] = ['user01','user01@example.com'];

# If you are running roundcube in a reverse proxy environment, enable it.
# When enabled, the plugin internally determines the connection using 
# the X_FORWAREDED_FOR header information as the connection source IP address.
$config['proxyenabled'] = false;

# If proxyenabled is enabled, set the IP address of the trusted proxy.
# Multi-stage proxies are currently not supported.
$config['trusted_proxy'] = "";

```
