#!/usr/bin/perl
use strict;
use warnings;

use Socket;
use LWP::UserAgent;

my %rkn;

# Load config
open CFG, "./bl_check.conf" or die "Create bl_check.conf";
my $config  = join "",<CFG>;
close CFG;
eval $config;
die "Couldn't interpret the configuration file.\nError details follow: $@\n" if $@;

# load RKN list
my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 1 });
$ua->agent('Wget/1.12 (linux-gnu)');
my $res = $ua->get("https://reestr.rublacklist.net/api/v2/ips/csv");
 die "Couldn't get it!" unless defined $res;


foreach (split(",",$res->decoded_content)) {
    $_=~s/[\n\r]//g;
    $rkn{$_}=1;
}

my $net_start = unpack("N",inet_aton("104.24.118.0"));
my $net_stop  = unpack("N",inet_aton("104.24.118.255"));

for (my $i=$net_start; $i<=$net_stop; $i+=1) {
    my $addr = inet_ntoa(pack("N",$i));
    my $res = check($addr);
    if ( $res ne "" ) {
        printf("ip %s in lists %s\n",$addr,$res);
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
    my $addr = sprintf("%s..dnsbl.zapbl.net",inet_reverse(shift));
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

#    SpamCop: www.spamcop.net
#    SBL (SpamHaus Blocklist): https://www.spamhaus.org/sbl/
#    PBL (Spamhaus Policy Block List): https://www.spamhaus.org/pbl/
#    SORBS (Spam and Open Relay Blocking System: www.sorbs.net
#    OPM (Open Proxy Monitor List): www.blitzed.org
#    CBL (Composite Blocking List): cbl.abuseat.org
#    Five-Ten Blocklist: www.five-ten-sg.com
#    MAPS (Trend Micro DNSBL): https://www.ers.trendmicro.com/
