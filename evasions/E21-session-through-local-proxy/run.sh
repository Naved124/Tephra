#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs in the application container of the scenario's pod.
perl - <<'PL' || exit 99
use strict; use warnings; use IO::Socket::INET;
my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => 9001, Timeout => 10) or die "connect: $!";
my $n = 0;
while (my $line = <$s>) {
    my @w = split ' ', $line;
    last if !@w || $w[0] eq 'exit';
    my $out = '?';
    if ($w[0] eq 'ls') { opendir(my $d, $w[1]) or next; $out = join(" ", readdir $d); }
    elsif ($w[0] eq 'cat') { open(my $f, '<', $w[1]) or next; local $/; $out = <$f>; }
    print $s "$out\n"; $s->flush; $n++;
}
close $s;
die "no command arrived\n" if $n == 0;
print "ran $n commands from the listener through the proxy\n";
PL
