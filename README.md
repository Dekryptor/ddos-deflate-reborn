ddos-deflate-reborn
===================

This is a Perl rewrite of the (D)Dos Deflate script found at http://deflate.medialayer.com/

### Requirements

- Perl

### Mode of operation

Uses UFW (Uncomplicated Firewall) or iptables to ban IPs which maintain a large amount of connections over a period of time.

### Installation

- Edit the configuration variables in the script.
- Edit the whitelist in "whitelist.ddos".
- Create a cronjob to run the script every x seconds. The script should run more often than the $offender_timeout config variable, or no IPs will ever be banned.
 - Example: run script once every minute: * * * * * perl /path/to/script/ddos.pl

### License

This software is licenced under the [GNU General Public License v3 (GPL-3)](http://www.tldrlegal.com/license/gnu-general-public-license-v3-%28gpl-3%29).
