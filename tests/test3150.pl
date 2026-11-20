#!/sw/perl/bin/perl
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
#
# Fluffy: wildcard --cacert/--capath/--crlfile against a loopback
# "openssl s_server", with a CA/leaf/CRL fixture laid out like late-bound
# /sw/<pkg>/etc/ssl trees in a private directory.
#
# Usage: test3150.pl local|live|precheck-live <workdir> <curl>
#
#   local          the private fixture checks (test 3150)
#   live           the installed /sw/*/etc/ssl/certs/ca-certificates.crt
#                  wildcard loads, and does not trust the fixture root
#                  (test 3151)
#   precheck-live  prints a reason (= skip) when no installed bundle exists
#
# Exits 0 when every check passes; diagnostics go to stderr.

use strict;
use warnings;

use Cwd qw(getcwd);
use File::Copy;
use File::Path qw(make_path rmtree);
use File::Spec::Functions qw(rel2abs);
use IO::Socket::INET;
use POSIX qw(:sys_wait_h);

my $live_bundle = '/sw/*/etc/ssl/certs/ca-certificates.crt';

my ($mode, $td, $curl) = @ARGV;
die "usage: $0 local|live|precheck-live <workdir> <curl>\n"
    unless defined $mode;

if($mode eq 'precheck-live') {
    print "no installed CA bundle matches $live_bundle\n"
        unless grep { -f $_ && -r _ } glob($live_bundle);
    exit 0;
}
die "usage: $0 local|live <workdir> <curl>\n"
    unless defined $curl && ($mode eq 'local' || $mode eq 'live');

$td = rel2abs($td);
$curl = rel2abs($curl);
die "$curl: not executable\n" unless -x $curl;

# PATH may itself hold wildcard entries (/sw/*/bin); expand them.
sub findcmd {
    my ($name) = @_;
    for my $d (split(/:/, $ENV{'PATH'} // '')) {
        next if $d eq '';
        for my $e (($d =~ /[*?\[]/) ? glob($d) : ($d)) {
            return "$e/$name" if -f "$e/$name" && -x _;
        }
    }
    return undef;
}
my $openssl = $ENV{'OPENSSL'} || findcmd('openssl')
    or die "openssl: not found in PATH\n";

my $failed = 0;
my $n = 0;
sub check {
    my ($ok, $desc) = @_;
    $n++;
    print(($ok ? "ok" : "not ok") . " $n - $desc\n");
    $failed++ unless $ok;
}

# Run a command; stdout and stderr go to files. Returns the exit status.
sub runcmd {
    my ($out, $err, @cmd) = @_;
    my $pid = fork();
    die "fork: $!" unless defined $pid;
    if(!$pid) {
        open(STDIN, '<', '/dev/null');
        open(STDOUT, '>', $out) or die "$out: $!";
        open(STDERR, '>', $err) or die "$err: $!";
        exec { $cmd[0] } @cmd;
        die "exec $cmd[0]: $!";
    }
    waitpid($pid, 0);
    return ($? & 0x7f) ? 128 + ($? & 0x7f) : ($? >> 8);
}

sub slurp {
    my ($f) = @_;
    open(my $fh, '<', $f) or return '';
    local $/;
    my $s = <$fh>;
    close($fh);
    return $s // '';
}

sub spew {
    my ($f, $s) = @_;
    open(my $fh, '>', $f) or die "$f: $!";
    print $fh $s;
    close($fh) or die "$f: $!";
}

sub ossl {
    my $rc = runcmd("$td/ossl.out", "$td/ossl.err", $openssl, @_);
    if($rc) {
        print STDERR "openssl @_ => $rc\n", slurp("$td/ossl.err");
        die "fixture: openssl $_[0] failed\n";
    }
    return slurp("$td/ossl.out");
}

rmtree($td);
make_path(map { "$td/$_" } "sw/pkgA/etc/ssl/certs", "sw/pkgB/etc/ssl/certs",
          "sw/pkgA/etc/ssl/crl", "sw/pkgB/etc/ssl/crl", "empty_capath",
          "cwd", "ca_db");

# A private, minimal configuration: never the host's or /sw's openssl.cnf.
spew("$td/openssl.cnf", "[ req ]\ndistinguished_name = req_dn\n[ req_dn ]\n");
$ENV{'OPENSSL_CONF'} = "$td/openssl.cnf";
delete $ENV{$_} for qw(CURL_CA_BUNDLE SSL_CERT_FILE SSL_CERT_DIR);

my @ca_ext = ("-addext", "basicConstraints=critical,CA:TRUE",
              "-addext", "keyUsage=critical,keyCertSign,cRLSign");
ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
     "-subj", "/CN=Fluffy Trusted Root", @ca_ext,
     "-keyout", "$td/ca1.key", "-out", "$td/ca1.pem");
ossl("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=127.0.0.1",
     "-addext", "basicConstraints=CA:FALSE",
     "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost",
     "-keyout", "$td/srv.key", "-out", "$td/srv.csr");
ossl("x509", "-req", "-days", "1", "-in", "$td/srv.csr",
     "-CA", "$td/ca1.pem", "-CAkey", "$td/ca1.key", "-CAcreateserial",
     "-copy_extensions", "copyall", "-out", "$td/srv.pem");
ossl("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
     "-subj", "/CN=Fluffy Untrusted Root", @ca_ext,
     "-keyout", "$td/ca2.key", "-out", "$td/ca2.pem");

my $h1 = ossl("x509", "-hash", "-noout", "-in", "$td/ca1.pem");
chomp $h1;
die "fixture: bad subject hash '$h1'\n" unless $h1 =~ /^[0-9a-f]{8}$/;

# pkgA: an empty bundle that sorts first; pkgB: the real bundle and hash
# link; the current directory: a hash link that must never be consulted.
copy("$td/ca1.pem", "$td/sw/pkgB/etc/ssl/certs/ca-certificates.crt")
    or die "copy: $!";
symlink("$td/ca1.pem", "$td/sw/pkgB/etc/ssl/certs/$h1.0") or die "ln: $!";
spew("$td/sw/pkgA/etc/ssl/certs/ca-certificates.crt", "");
symlink("$td/ca1.pem", "$td/cwd/$h1.0") or die "ln: $!";

spew("$td/ca_db/index.txt", "");
spew("$td/ca_db/crlnumber", "01\n");
spew("$td/ca.cnf", <<"EOF");
[ ca ]
default_ca = CA_default
[ CA_default ]
database = $td/ca_db/index.txt
crlnumber = $td/ca_db/crlnumber
default_md = sha256
default_crl_days = 1
EOF
ossl("ca", "-config", "$td/ca.cnf", "-keyfile", "$td/ca1.key",
     "-cert", "$td/ca1.pem", "-gencrl",
     "-out", "$td/sw/pkgB/etc/ssl/crl/ca1.pem");
spew("$td/sw/pkgA/etc/ssl/crl/empty.pem", "");

# Loopback TLS server.
my ($srv, $port);
sub stopserver {
    return unless $srv;
    kill('TERM', $srv);
    for(1 .. 100) {
        if(waitpid($srv, WNOHANG) != 0) {
            $srv = undef;
            return;
        }
        select(undef, undef, undef, 0.05);
    }
    kill('KILL', $srv);
    waitpid($srv, 0);
    $srv = undef;
}
# Never leave the server behind, even when a check dies.
END { my $rc = $?; stopserver(); $? = $rc; }
for my $try (1 .. 5) {
    my $s = IO::Socket::INET->new(LocalAddr => '127.0.0.1', LocalPort => 0,
                                  Proto => 'tcp', Listen => 1)
        or die "socket: $!";
    $port = $s->sockport();
    close($s);
    $srv = fork();
    die "fork: $!" unless defined $srv;
    if(!$srv) {
        # The test runner may leave TERM ignored; do not pass that on.
        $SIG{$_} = 'DEFAULT' for qw(TERM INT HUP PIPE);
        open(STDIN, '<', '/dev/null');
        open(STDOUT, '>', "$td/srv.log");
        open(STDERR, '>&', \*STDOUT);
        exec { $openssl } $openssl, "s_server", "-www", "-quiet",
            "-accept", "127.0.0.1:$port",
            "-cert", "$td/srv.pem", "-key", "$td/srv.key";
        die "exec $openssl: $!";
    }
    my $up = 0;
    for(1 .. 200) {
        last if waitpid($srv, WNOHANG) == $srv;
        my $c = IO::Socket::INET->new(PeerAddr => '127.0.0.1',
                                      PeerPort => $port, Proto => 'tcp',
                                      Timeout => 1);
        if($c) {
            close($c);
            $up = 1;
            last;
        }
        select(undef, undef, undef, 0.05);
    }
    last if $up;
    stopserver();
    print STDERR "s_server did not come up on port $port (try $try):\n",
        slurp("$td/srv.log");
    $srv = undef;
}
die "could not start openssl s_server\n" unless $srv;

my $url = "https://127.0.0.1:$port/";
my $i = 0;
sub curl {
    $i++;
    my $rc = runcmd("$td/curl$i.out", "$td/curl$i.err", $curl, "-q",
                    "--silent", "--show-error", "--fail", "--noproxy", "*",
                    "--max-time", "60", @_, $url);
    print STDERR "curl @_ => $rc\n", slurp("$td/curl$i.err") if $rc;
    return $rc;
}

my $cwd = getcwd();
chdir("$td/cwd") or die "chdir: $!";

if($mode eq 'local') {
    check(curl("--cacert", "$td/sw/*/etc/ssl/certs/ca-certificates.crt",
               "--capath", "/nonexistent") == 0,
          "--cacert wildcard skips an empty match");
    check(curl("--cacert", "$td/sw/*/etc/ssl/certs/ca-certificates.crt",
               "--crlfile", "$td/sw/*/etc/ssl/crl/*.pem",
               "--capath", "/nonexistent") == 0,
          "--crlfile wildcard skips an empty match");
    check(curl("--cacert", "$td/ca2.pem",
               "--capath", ":$td/sw/*/etc/ssl/certs") == 0,
          "--capath wildcard list with a leading ':'");
    check(curl("--cacert", "$td/ca2.pem", "--capath", ".") == 0,
          "control: the current directory does hold the server's root");
    check(curl("--cacert", "$td/ca2.pem",
               "--capath", ":$td/empty_capath:") == 60,
          "--capath empty segments never mean the current directory (60)");
    my $rc = curl("--cacert", "$td/sw/*/nonexistent/*.crt");
    check($rc == 77, "--cacert wildcard without matches fails (77)");
    check(index(slurp("$td/curl$i.err"),
                "error adding trust anchors from file:") >= 0,
          "... and reports the trust anchor file");
}
else {
    check(curl("--cacert", $live_bundle, "--capath", "/nonexistent") == 60,
          "installed $live_bundle loads and does not trust the fixture (60)");
}

chdir($cwd);
stopserver();
exit($failed ? 1 : 0);
