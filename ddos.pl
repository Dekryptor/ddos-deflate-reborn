#!/usr/bin/perl

use strict;
use warnings;
use integer;

### start config ###

# if an IP has more than $max_connections amount of connections to the server
my $max_connections = 1;
# more than $max_offences times (number of times caught by the script)
my $max_offences = 5;
# within $offender_timeout seconds
my $offender_timeout = 30;
# it gets banned.

# debug mode: change this to 0 to ban IPs for real
my $debug_only = 1;
# whitelist file. add one IP per line.
my $whitelist_file = "whitelist.ddos";
# offenders tracking output file
my $offence_tracker_file = "offenders.ddos";

### end config, below be dragons ###

my $ufw_check = qx(ufw status 2>&1);

if ($ufw_check =~ /.*error.*/i) {
   print "This script must have UFW permissions (usually this means it needs to run as root)" . "\n";
}

elsif ($ufw_check =~ /.*inactive.*/i) {
   print "UFW is inactive. It must be activated. Don't enable a firewall unless you know what you're doing! Try: sudo ufw enable" . "\n";
}

elsif ($ufw_check =~ /.*active.*/i) {

   my %ips;
   my %offending_ips;
   my %whitelist_ips;
   my $now = time();
   
   # read in the whitelist
   if (open (my $fhr, "<", "$whitelist_file")) {
      while (my $line = <$fhr>) {
         if ($line =~ /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/) {
            $whitelist_ips{$1} = 1;
         }
      }
   }
   
   # read in the previously logged ips that went over the threshold
   if (open (my $fhr, "<", "$offence_tracker_file")) {
      while (my $line = <$fhr>) {
         # get the offending_ips_current and number of times it's passed the $max_connections threshold
         if ($line =~ /([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+) ([0-9]+) ([0-9]+)/) {
            $offending_ips{$1} = $2 . " " . $3;
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
   open ($fhw, ">", "$offence_tracker_file") or die "ERROR: cannot open $offence_tracker_file for writing: $!";

   # go through all the active ips
   while ((my $ip, my $connections) = each(%ips)) {
      # if an IP is over the limit
      if ($connections > $max_connections) {
      
         # skip if in whitelist
         if ($whitelist_ips{$ip}) {
            next;
         }
      
         # how many times has this IP offended?
         if (!$offending_ips{$ip}) {
            $offending_ips{$ip} = 0 . " " . $now;
         }
         
         (my $num, my $time) = split (/\s/, $offending_ips{$ip});
         $num++;
         
         # ban the ip if it's offended too many times
         if ($num > $max_offences) {
            print "Banning: " . $ip . " .. ";
 
            my $ufw_ret;
            if ($debug_only) {
               $ufw_ret = qx(ufw --dry-run insert 1 deny from $ip);
            }
            else {
               $ufw_ret = qx(ufw insert 1 deny from $ip);
            }
            
            if ($ufw_ret eq "Rule inserted") {
               print "success." . "\n";
            } else {
               print "failure: " . $ufw_ret . "\n";
            }
         }
         
         else {
            # if the logged ip hasn't expired, write it to file
            if ($now - $time < $offender_timeout) {
               print {$fhw} $ip . " " . $num . " " . $now . "\n";
            }
         }
      }
   }

   close($fhw);
}

else {
   print "Unknown error.";
}
