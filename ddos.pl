#!/usr/bin/env perl

use strict;
use warnings;
use integer;

my %config;

### start config ###

# if an IP has more than max_connections connections to the server
$config{'max_connections'} = 150;
# more than max_offences times (number of times caught by the script)
$config{'max_offences'} = 3;
# it gets banned.

# an offending IP will be taken off the list if it has not offended in offender_timeout seconds
$config{'offender_timeout'} = 120;

# use UFW (Uncomplicated Firewall) to block IPs. if set to 0, iptables will be used
$config{'use_ufw'} = 1;
# debug mode: change this to 0 to ban IPs for real
$config{'debug_only'} = 1;

# whitelist file. add one IP per line.
$config{'whitelist_file'} = 'whitelist.ddos';
# offenders tracking output file
$config{'offence_tracker_file'} = 'offenders.ddos';

### end config. below be dragons ###

my $fw_check;

if ($config{'use_ufw'}) {
   $fw_check = qx(ufw status 2>&1);
} else {
   $fw_check = qx(iptables --check 1 2>&1);
}

if ($fw_check =~ /.*error.*/i or $fw_check =~ /.*denied.*/i) {
   print 'This script must have ufw/iptables permissions (usually this means it needs to run as root)' . "\n";
}

elsif ($fw_check =~ /.*inactive.*/i) {
   print 'UFW is inactive. It must be activated. Don\'t enable a firewall unless you know what you\'re doing! Try: sudo ufw enable' . "\n";
}

elsif ($fw_check =~ /.*active.*/i or $fw_check =~ /.*chain.*/i) {

   my %ips;
   my %offending_ips;
   my %whitelist_ips;
   my $now = time();
   
   # read in the whitelist
   if (open (my $fhr, '<', $config{'whitelist_file'})) {
      while (my $line = <$fhr>) {
         if ($line =~ /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/) {
            $whitelist_ips{$1} = 1;
         }
      }
   }
   
   # read in the previously logged ips that went over the threshold
   if (open (my $fhr, '<', $config{'offence_tracker_file'})) {
      while (my $line = <$fhr>) {
         # get the offending_ips_current and number of times it's passed the $config{'max_connections'} threshold
         if ($line =~ /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ([0-9]+) ([0-9]+)/) {
            $offending_ips{$1} = $2 . ' ' . $3;
         }
      }
   }

   # get all the active IPs used on the system from netstat
   my $output = qx(netstat -ntu);
   foreach my $line (split /[\r\n]+/, $output) {
      # put all the info from netstat into variables. we're only using one at the moment, but this might change
      if ($line =~ /([tcp|udp])\s+([0-9]+)\s+([0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+):([0-9]+)\s+([a-zA-Z]+)/) {
         # count how many times this IP is seen
         $ips{$6}++;
      }
   }
   
   # open the tracking file for writing
   my $fhw;
   open ($fhw, '>', $config{'offence_tracker_file'}) or die 'ERROR: cannot open '. $config{'offence_tracker_file'} ." for writing: $!";

   # go through all the active ips
   while ((my $ip, my $connections) = each(%ips)) {
      # if an IP is over the limit
      if ($connections > $config{'max_connections'}) {
      
         # skip if in whitelist
         if ($whitelist_ips{$ip}) {
            next;
         }
      
         my $num_offences;
         my $last_offence_time;
      
         # ip was not on offenders list
         if (!$offending_ips{$ip}) {
            $num_offences = 1;
            $last_offence_time = $now;
         }
         # ip has offended before
         else {
            ($num_offences, $last_offence_time) = split (/\s/, $offending_ips{$ip});
            
            # skip this ip if it has timed out.
            if ($now - $last_offence_time > $config{'offender_timeout'}) {
               next;
            }
            
            $num_offences++;
         }
         
         # ban the ip if it's offended too many times
         if ($num_offences > $config{'max_offences'}) {
            print 'Banning: ' . $ip . ' .. ';
 
            my $fw_cmd;
            my $fw_ret;
            
            # use UFW (Uncomplicated Firewall)
            if ($config{'use_ufw'}) {
            
               $fw_cmd = 'ufw '.($config{'debug_only'} ? '--dry-run' : '').' insert 1 deny from '.$ip.' 2>&1';
            
               $fw_ret = qx($fw_cmd);

               if ($fw_ret =~ /invalid position/i) {
                  $fw_cmd = 'ufw '.($config{'debug_only'} ? '--dry-run' : '').' deny from '.$ip.' 2>&1';
                  $fw_ret = qx($fw_cmd);
               }
               
               if ($fw_ret =~ /rule inserted/i or $fw_ret =~ /rules updated/i) {
                  print 'success' . ($config{'debug_only'} ? ' (dry-run, no rule actually added)' : '.') . "\n";
               } else {
                  print 'failure: ' . $fw_ret . "\n";
               }
            }
            
            # use IPtables
            else {
               if ($config{'debug_only'}) {
                  print '(dry-run, no rule actually added)' . "\n";
               }
               else {
                  $fw_cmd = 'iptables -I INPUT -s '.$ip.' -j DROP 2>&1';
                  $fw_ret = qx($fw_cmd);
               }
               
               if (chomp($fw_ret) eq '') {
                  print 'success.';
                  qx(service iptables save);
               }
               else {
                  print 'failure: ' . $fw_ret . "\n";
               }
            }
         }
         
         # if not over offending threshold
         else {
            # write ip to offenders file
            print {$fhw} $ip . ' ' . $num_offences . ' ' . $now . "\n";
         }
      }
   }

   close($fhw);
}

else {
   print 'Unknown error.';
}
