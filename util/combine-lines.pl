#!/usr/bin/perl
# 05nov2016 mwall
# take CGI arguments split over multiple lines and combine into a single
# line of CGI arguments suitable for reposting to a web server
#
# sample input:
#
# GET /weatherstation/updateweatherstation?dateutc=now&action=updateraw&
# realtime=1&id=24C86E06B15C&mt=5N1x31&sensor=00002179&windspeedmph=0&
# winddir=113&rainin=0.00&dailyrainin=0.55&humidity=50&tempf=59.2&dewptf=41&
# baromin=29.35&battery=normal&rssi=3 HTTP/1.1
# Host: hubapi.myacurite.com
# User-Agent: Hub/224
# Connection: close
#
# GET /weatherstation/updateweatherstation.php?ID=XXX&PASSWORD=XXXXXXXX&
# dateutc=now&action=updateraw&realtime=1&rtfreq=36&id=24C86E06B15C&mt=5N1x31&
# sensor=00002179&windspeedmph=0&winddir=113&rainin=0.00&dailyrainin=0.55&
# humidity=50&tempf=59.2&dewptf=41&baromin=29.35&battery=normal&rssi=3 HTTP/1.1
# Host: rtupdate.wunderground.com
# Connection: close
#
# sample usage:
#
# tcpdump -i eth0 src X.X.X.X and port 80 | combine-lines.pl

use strict;

my $out = q();
while(my $line=<>) {
    $line =~ s/\s$//g; # punt any trailing whitespace
    if($line =~ /^GET/) {
        # flush any previous line
        flush($out);
        # start a new line
        ($out) = $line =~ /^GET (.*)/;
    } elsif($line eq q() || $line !~ /\S/ || $line =~ /:/) {
        # skip lines such as these:
        # Host: example.com
        # User-Agent: Hub/224
        # Connection: close
        flush($out);
        $out = q()
    } else {
        $out .= $line;
    }
}

exit 0;


sub flush {
    my($line) = @_;
    if($line ne q()) {
        $line =~ s%^.*\?%%; # remove anything before the args
        $line =~ s% HTTP/1.1%%; # remove dangling HTTP if there is one
        print STDOUT "$line\n";
    }
}
