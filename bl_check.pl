#!/usr/bin/perl
use strict;
use warnings;

use Socket;
use LWP::UserAgent;
use Net::DNS::Async;
use Data::Dumper;

my %NETS;
my %RES;
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

my $c = new Net::DNS::Async(QueueSize => 100, Retries => 3);

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
        check($addr);
    }
}

$c->await();

foreach (sort(keys %RES)) {
    printf "%s in %s\n",$_ , join(" ",keys %{$RES{$_}});
}

sub inet_reverse {
    my $addr = shift;
    my @ip = split(/\./,$addr);
    return sprintf("%s.%s.%s.%s",int($ip[3]),int($ip[2]),int($ip[1]),int($ip[0]));
}

sub check {
    my $addr = shift;
    check_dnsbl($addr,"b.barracudacentral.org","BARRACUDA_DNSBL");
    check_dnsbl($addr,"zen.spamhaus.org","SPAMHAUS_DNSBL");
    check_dnsbl($addr,"spam.dnsbl.sorbs.net","SORBS_DNSBL");
    check_dnsbl($addr,"dnsbl.zapbl.net","ZAPBS_DNSBL");
    check_dnsbl($addr,"dnsbl.spfbl.net","SPFBL_DNSBL");
    check_dnsbl($addr,"all.spamrats.com","SPAMRATS_DNSBL");
    check_rkn($addr);
}

sub check_rkn {
    my $addr = shift;
    if (defined($rkn{$addr})) {
        $RES{$addr}->{RKN} = '1';
    }
}

sub check_dnsbl {
    my $addr = shift;
    my $domain = shift;
    my $marker = shift;
    $c->add( 
        sub {
            my $responce = shift;
            if ( $responce->header->ancount > 0 ) {
                my $ip = sprintf "%s",($responce->answer)[0]->address;
                $RES{$addr}->{$marker} = $ip;
            }
        }, (sprintf("%s.%s",inet_reverse($addr),$domain))
    );
}

=head1 REPOSITORY

L<https://github.com/whyberg/bl_check>

=head1 DISCLAIMER OF WARRANTIES

The software is provided "AS IS", without warranty of any kind, express or
implied, including but not limited to the warranties of merchantability,
fitness for a particular purpose and noninfringement. In no event shall the
authors or copyright holders be liable for any claim, damages or other
liability, whether in an action of contract, tort or otherwise, arising from,
out of or in connection with the software or the use or other dealings in
the software.

=head1 AUTHOR

Andrey Artemyev<whyberg@gmail.com>

=cut
