#!/usr/bin/perl

use strict;
use warnings;
use integer;

my $ufw_check = qx(ufw status 2>&1);

if ($ufw_check =~ /.*error.*/i) {
   print "This script must have UFW permissions (usually this means it needs to run as root)" . "\n";
}

elsif ($ufw_check =~ /.*inactive.*/i) {
   print "UFW is inactive. It must be activated. Don't enable a firewall unless you know what you're doing! Try: sudo ufw enable" . "\n";
}

else {

   my $offence_tracker_file = "offenders.ddos";
   # if an IP has more than $max_connections amount of connections
   my $max_connections = 1;
   # more than $max_intervals times 
   my $max_intervals = 5;
   # within $expiry_time seconds
   my $expiry_time = 10;
   # it gets banned.

   my %ips;
   my %offending_ips;
   my $now = time();

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

   # open the file for writing
   my $fhw;
   open ($fhw, ">", "$offence_tracker_file");

   # go through all the active ips
   while ((my $ip, my $connections) = each(%ips)) {
      # if an IP is over the limit
      if ($connections > $max_connections) {
      
         # how many times has this IP offended?
         if (!$offending_ips{$ip}) {
            $offending_ips{$ip} = 0 . " " . $now;
         }
         
         (my $num, my $time) = split (/\s/, $offending_ips{$ip});
         $num++;
         
         # ban the ip if it's offended too many times
         if ($num > $max_intervals) {
            print $ip . " " . $connections . "\n";
         }
         
         else {
            # if the logged ip hasn't expired, write it to file
            if ($now - $time < $expiry_time) {
               print {$fhw} $ip . " " . $num . " " . $now . "\n";
            }
         }
      }
   }

   close($fhw);
}
