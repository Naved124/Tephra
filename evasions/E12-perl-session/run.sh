#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Lab use only. Runs inside the scenario's target pod.
perl - <<'PL' || exit 99
use strict; use warnings; use IO::Socket::INET;
my $srv = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 9001, Listen => 1, ReuseAddr => 1) or die "listen: $!";
my $pid = fork() // die "fork: $!";
if ($pid == 0) {
    my $c = $srv->accept or exit 1;
    for my $cmd ("ls /\n", "cat /etc/hostname\n", "exit\n") {
        print $c $cmd; $c->flush;
        last if $cmd eq "exit\n";
        my $r = ''; $c->recv($r, 4096); print "session said: $r";
    }
    close $c; exit 0;
}
my $s = IO::Socket::INET->new(PeerAddr => '127.0.0.1', PeerPort => 9001) or die "connect: $!";
while (my $line = <$s>) {
    my @w = split ' ', $line;
    last if !@w || $w[0] eq 'exit';
    my $out = '?';
    if ($w[0] eq 'ls') { opendir(my $d, $w[1]) or next; $out = join("\n", readdir $d); }
    elsif ($w[0] eq 'cat') { open(my $f, '<', $w[1]) or next; local $/; $out = <$f>; }
    print $s "$out\n"; $s->flush;
}
close $s; waitpid($pid, 0);
PL
