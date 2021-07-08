#!/usr/bin/perl
use strict;
use warnings;

use Socket;
use LWP::UserAgent;

my %NETS;
# Load config
open CFG, "./bl_check.conf" or die "Create bl_check.conf";
my $config  = join "",<CFG>;
close CFG;
eval $config;
die "Couldn't interpret the configuration file.\nError details follow: $@\n" if $@;

my %rkn;
# load RKN list
my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 1 });
$ua->agent('Wget/1.12 (linux-gnu)');
my $res = $ua->get("https://reestr.rublacklist.net/api/v2/ips/csv");
 die "Couldn't get rkn blacklist!" unless defined $res;
foreach (split(",",$res->decoded_content)) {
    $_=~s/[\n\r]//g;
    $rkn{$_}=1;
}

foreach (sort(keys(%NETS))) {
    my $full_mask  = unpack( "N", pack( "C4", 255,255,255,255 ) );
    my $net_start;
    my $net_stop;
    my ($ip_t,$mask_t) = split("/",$NETS{$_});
    if ( defined($mask_t) ) {
        my $mask = 1;
        $mask = ( 2 ** (32 - $mask_t) ) - 1;
        $net_start = unpack("N",inet_aton($ip_t)) & ( $full_mask ^ $mask );
        $net_stop = unpack("N",inet_aton($ip_t)) | $mask;
        printf "Check range: from %s to %s\n",inet_ntoa(pack("N",$net_start)),inet_ntoa(pack("N",$net_stop));
    } else {
        $net_start = unpack("N",inet_aton($ip_t));
        $net_stop = $net_start;
        printf "Check ip: %s\n",inet_ntoa(pack("N",$net_start));
    }
    for (my $i=$net_start; $i<=$net_stop; $i+=1) {
        my $addr = inet_ntoa(pack("N",$i));
        my $res = check($addr);
        if ( $res ne "" ) {
            printf("ip %s in lists %s\n",$addr,$res);
        }
    }
}

sub inet_reverse {
    my $addr = shift;
    my @ip = split(/\./,$addr);
    return sprintf("%s.%s.%s.%s",int($ip[3]),int($ip[2]),int($ip[1]),int($ip[0]));
}

sub check {
    my $addr = shift;
    my $BLS = check_barracudacentral($addr).
              check_spamhaus($addr).
              check_spfbl($addr).
              check_zapbl($addr).
              check_sorbs($addr).
              check_rkn($addr);
    return $BLS;
}

sub check_rkn {
    my $addr = shift;
    if (defined($rkn{$addr})) {
        return "RKN ";
    }     
}

sub check_barracudacentral {
    my $addr = sprintf("%s.b.barracudacentral.org",inet_reverse(shift));
    my $packed_ip = gethostbyname($addr);
    if (defined $packed_ip) {
        return "BARRACUDA_DNSBL ";
    }
}

sub check_spamhaus {
    my $addr = sprintf("%s.zen.spamhaus.org",inet_reverse(shift));
    my $packed_ip = gethostbyname($addr);
    if (defined $packed_ip) {
        return "SPAMHAUS_DNSBL ";
    }
}

sub check_sorbs {
    my $addr = sprintf("%s.spam.dnsbl.sorbs.net",inet_reverse(shift));
    my $packed_ip = gethostbyname($addr);
    if (defined $packed_ip) {
        return "SORBS_DNSBL ";
    }
}

sub check_zapbl {
    my $addr = sprintf("%s.dnsbl.zapbl.net",inet_reverse(shift));
    print $addr;
    my $packed_ip = gethostbyname($addr);
    if (defined $packed_ip) {
        return "ZAPBS_DNSBL ";
    }
}

sub check_spfbl {
    my $addr = sprintf("%s.dnsbl.spfbl.net",inet_reverse(shift));
    my $packed_ip = gethostbyname($addr);
    if (defined $packed_ip) {
        if (inet_ntoa($packed_ip) eq "127.0.0.2") {
            return "SPFBL_DNSBL ";
        }
    }
}
