<?php
/**
 * restrict_user_access
 *
 *  Plugin to allow login from restricted networks. Certain users can also be granted all access.
 *
 * @version 1.0
 * @license GNU GPLv3+
 * @author shogo mori<smori@designet.co.jp>
 */
class restrict_user_access extends rcube_plugin
{
    public function init()
    {
        $this->add_hook('authenticate', [$this, 'authenticate']);
    }

    public function authenticate($args)
    {
        $this->load_config();
        $conf_allowed_v4networks = rcmail::get_instance()->config->get('allowed_ipv4_networks', []);
        $conf_allowed_v6networks = rcmail::get_instance()->config->get('allowed_ipv6_networks', []);
        $conf_whiteusers = rcmail::get_instance()->config->get('whitelist_users', []);
        $conf_proxyenabled = rcmail::get_instance()->config->get('proxyenabled', false);

        # Allow white list user
        foreach ($conf_whiteusers as $user) {
            if ($args['user'] === $user) {
                return $args;
            }
        }

	# Get source ip address
        $remoteip = $_SERVER['REMOTE_ADDR'];
        if ($conf_proxyenabled === true && isset($_SERVER["HTTP_X_FORWARDED_FOR"])) {
            $remoteip = $_SERVER["HTTP_X_FORWARDED_FOR"];
        }

	$remoteip= "2001:268:35d::53:1";

	# IPv4 check
	$isIPv4 = filter_var($remoteip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4);
	if ($isIPv4 !== false) {
           # allow v4 networks
           foreach ($conf_allowed_v4networks as $network) {
               $ret = $this->isIPv4InNetwork($remoteip, $network);
               if ($ret === True) {
                   return $args;
               }
           }
	} 

	# IPv6 check
	$isIPv6 = filter_var($remoteip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6);
	if ($isIPv6 !== false) {
           # allow v4 networks
           foreach ($conf_allowed_v6networks as $network) {
               $ret = $this->isIPv6InNetwork($remoteip, $network);
               if ($ret === True) {
                   return $args;
               }
           }
	}

        $args["abort"] = true;
        return $args;
    }

    private function isIPv6InNetwork($remoteip, $network) {
        [$networkAddress, $prefixLength] = explode('/', $network);
        $ip = inet_pton($remoteip);
        $network = inet_pton($networkAddress);

        $binaryMask = str_repeat('1', $prefixLength) . str_repeat('0', 128 - $prefixLength);
        $mask = pack('H*', $binaryMask);

        $ipNetworkPart = substr($ip & $mask, 0, $prefixLength / 8);
        $networkNetworkPart = substr($network & $mask, 0, $prefixLength / 8);

        return $ipNetworkPart === $networkNetworkPart;
    }

    private function isIPv4InNetwork($remoteip, $network) {
        [$networkAddress, $mask] = explode('/', $network);
        $allowed = ip2long($networkAddress,) >> (32 - $mask);
        $remote  = ip2long($remoteip) >> (32 - $mask);

        return $allowed === $remote;
    }
}
