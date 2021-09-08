#!/usr/bin/perl
use strict;
use warnings;

use Socket;
use LWP::UserAgent;
use Net::DNS::Async;

use Storable;

my %NETS;
my %BL;
my %RES;
my %rkn;
my $c;
my $resfilename = './bl_check.res';
my $conffilename = 'bl_check.conf';

my $extreport = 0;
my $fastreport = 0;

# extract command line
for ( my $i = 0 ; $i <= $#ARGV ; $i++ ) {
    my $valid = $ARGV[$i];
    if ( substr( $ARGV[$i], 0, 1 ) ne '-' ) {
        $valid = '';
    }
    elsif ( $ARGV[$i] eq '-c' ) {
        $conffilename = $ARGV[ ++$i ];
        $valid = '';
    }
    elsif ( $ARGV[$i] eq '-e' ) {
        $extreport = 1;
        $valid = '';
    }
    elsif ( $ARGV[$i] eq '-f' ) {
        $fastreport = 1;
        $valid = '';
    }
    elsif ( $ARGV[$i] eq '-h' ) {
        usage();
        exit;
    }
    if ($valid) {
        print "Invalid option '$valid'\n";
        usage();
        exit;
    }
}


# Load config
open CFG, $conffilename or die "Config ".$conffilename." not found!\n";
my $config  = join "",<CFG>;
close CFG;
eval $config;
die "Couldn't interpret the configuration file.\nError details follow: $@\n" if $@;

if ( -e $resfilename and $fastreport ) {
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

sub usage {
    my $usage_t = qq{
    Usage: bl_check.pl [OPTIONS]

    Options:
        -c [filename]
            use [filename] as configuration file name (bl_check.conf default)
        -e
            show extended report
        -f
            use fast report
        -h 
            show this message
    };
    print $usage_t;
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
