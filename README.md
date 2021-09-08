# bl_check
> DNSBL command line checker utility

##  Prerequisites

This project requires Perl5

## Installation

**BEFORE YOU INSTALL:** please read the [prerequisites](#prerequisites)

Start with cloning this repo on your local machine:

```sh
$ git clone https://github.com/whyberg/bl_check.git
$ cd PROJECT
```

Install required modules from CPAN:

```sh
$ cpan install LWP
$ cpan install Net::DNS::Async
```

Or if you prefer using apt:

```sh
$ apt install libwww-perl
$ apt install liblwp-protocol-https-perl
```
## Usage

Create config file from bl_check.conf.sample.

Add your networks CIDRs

