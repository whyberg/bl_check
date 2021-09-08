#!/usr/bin/perl
use strict;
use warnings;

use Socket;
use LWP::UserAgent;
use Net::DNS::Async;
use Data::Dumper;

use Storable;

my %NETS;
my %BL;
my %RES;
my %rkn;
my $c;
my $resfilename = './bl_check.res';
my $extreport = 0;

# Load config
open CFG, "./bl_check.conf" or die "Create bl_check.conf";
my $config  = join "",<CFG>;
close CFG;
eval $config;
die "Couldn't interpret the configuration file.\nError details follow: $@\n" if $@;

if ( -e $resfilename ) {
    %RES = %{retrieve($resfilename)};
} else {
    # load RKN list
    my $ua = LWP::UserAgent->new(ssl_opts => { verify_hostname => 1 });
    $ua->agent('Wget/1.12 (linux-gnu)');
    my $res = $ua->get("https://reestr.rublacklist.net/api/v2/ips/csv");
     die "Couldn't get rkn blacklist!" unless defined $res;
    foreach (split(",",$res->decoded_content)) {
        $_=~s/[\n\r]//g;
        $rkn{$_}=1;
    }

    $c = new Net::DNS::Async(QueueSize => 100, Retries => 3);

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

    store \%RES, $resfilename;
}

$BL{RKN}{code}{'1'} = 'Listed at RKN';

if ( $extreport == 0 ) {
    foreach (sort(keys %RES)) {
        printf "%s in %s\n",$_ , join(" ",keys %{$RES{$_}});
    }
} else {
    foreach (sort(keys %RES)) {
        my $ip = $_;
        printf "%s \n",$ip;
        foreach (sort(keys %{$RES{$ip}})) {
            printf "%5s %s\n","-->", $BL{$_}->{code}->{$RES{$ip}{$_}};
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
    foreach (keys %BL) {
        check_dnsbl($addr, $_, $BL{$_}->{service}, $BL{$_}->{code});
    }

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
    my $marker = shift;
    my $domain = shift;
    my $code = shift;

    $c->add(
        sub {
            my $responce = shift;
            if ( $responce->header->ancount > 0 ) {
                my $ip = sprintf "%s",($responce->answer)[0]->address;
                if ( defined(%$code{$ip}) ) {
                    $RES{$addr}->{$marker} = $ip;
                }
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
