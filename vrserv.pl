#!/usr/bin/perl -w

# Copyright 2004-2007 Ilkka Mattila, Joonas Kortesalmi
# All rights reserved.

use strict;

use Digest::MD5 qw(md5 md5_hex);

use Socket qw(inet_ntoa);
use POE qw( Wheel::SocketFactory  Wheel::ReadWrite
  Wheel::Run
  Component::Client::Ping
  Filter::Line          Driver::SysRW );

use Config::Tiny;
our (
    $secret, $port,         $debug,         $logfile,
    $ping,   $ping_timeout, $ping_interval, $reset,
    $addsh,  $delsh,        $resetsh,       $address
);

my $Config = Config::Tiny->new();
$Config = Config::Tiny->read('vrserv.ini');

$secret = $Config->{'connection'}->{'secret'}
  or die "Failed to read secret from vrserv.ini\n";
$address = $Config->{'connection'}->{'address'} or $address = 0.0.0.0;
$port = $Config->{'connection'}->{'port'} or $port = 31008;

$debug   = $Config->{'general'}->{'debug'}   or $debug   = 0;
$logfile = $Config->{'general'}->{'logfile'} or $logfile = 'logfile';

$ping 	       = $Config->{'pinger'}->{'enabled'}  or $ping = 0;
$ping_timeout  = $Config->{'pinger'}->{'timeout'}  or $ping_timeout  = 1;
$ping_interval = $Config->{'pinger'}->{'interval'} or $ping_interval = 10;

$reset = $Config->{'scripts'}->{'enable-reset'} or $reset = 0;
$addsh = $Config->{'scripts'}->{'addscript'}
  or die "Failed to read the location of add-script from vrserv.ini\n";
$delsh = $Config->{'scripts'}->{'delscript'}
  or die "Failed to read the location of del-script from vrserv.ini\n";
$resetsh = $Config->{'scripts'}->{'resetscript'}
  or die "Failed to read the location of reset-script from vrserv.ini\n";

$| = 1;

our ( %clients, %pingers );

delete $ENV{PATH};

POE::Session->create(

    inline_states => {
	    _start => \&server_start,
	    _stop  => \&server_stop,
            socket_birth => \&accept_new_client,
            socket_death => \&accept_failed,
    },


);

POE::Component::Client::Ping->spawn(
    Alias   => "pinger",
    Timeout => $ping_timeout,
);

unless ($debug) {
    my $pid;

    if ( !defined( $pid = fork() ) ) {
        die "Cannot fork: $!\n";
    }
    elsif ($pid) {
        print "Forking into background\n";
        exit 0;
    }

    # Forked successfully
    close STDOUT;
    open STDOUT, ">> $logfile";
    close STDERR;
    open STDERR, ">> $logfile";
    close STDIN;
    open STDIN, '/dev/null';
}

$poe_kernel->run();
exit;

sub server_start {
    $_[HEAP]->{listener} = POE::Wheel::SocketFactory->new(
        BindAddress  => $address,
        BindPort     => $port,
        Reuse        => 'yes',
        SuccessEvent => 'socket_birth',
        FailureEvent => 'socket_death'

    );
    print "SERVER: Started listening on port ", $port, ".\n";

    exec_shell( $_[HEAP], $resetsh ) if $reset;
}

sub server_stop {
    exec_shell( $_[HEAP], $resetsh ) if $reset;
    print "SERVER: Stopped.\n";
}

sub accept_new_client {
    my ( $socket, $peeraddr, $peerport ) = @_[ ARG0 .. ARG2 ];
    $peeraddr = inet_ntoa($peeraddr);

    print "SERVER: Got connection from $peeraddr:$peerport.\n" if $debug;

    POE::Session->create(
    	inline_states => {
	        _start => \&child_start,
	        _stop  => \&child_stop,
	        got_job_stderr => \&got_job_stderr,
	        got_job_close  => \&got_job_close,
	        pong           => \&got_pong_arp,
	},
	object_states => [
	        main   => [ 'child_input', 'child_done', 'child_error', 'child_flush' ],
	],
	args => [ $socket, $peeraddr, $peerport ],
    );

}

sub accept_failed {
    my ( $function, $error ) = @_[ ARG0, ARG2 ];

    delete $_[HEAP]->{listener};

    print "SERVER: call to $function() failed: $error.\n";
}

sub child_start {
    my ( $heap, $socket, $session ) = @_[ HEAP, ARG0, SESSION ];

    $heap->{readwrite} = new POE::Wheel::ReadWrite(
        Handle       => $socket,
        Driver       => new POE::Driver::SysRW(),
        Filter       => new POE::Filter::Line(),
        InputEvent   => 'child_input',
        ErrorEvent   => 'child_error',
        FlushedEvent => 'child_flush',
    );
    $heap->{peername} = join ':', @_[ ARG1, ARG2 ];
    $heap->{session}  = $session->ID;

    print "CHILD $heap->{session}: Connected to $heap->{peername}.\n";

    my $challenge = rand_md5();
    $heap->{readwrite}->put("+OK $challenge");
    $heap->{challenge}     = $challenge;
    $heap->{authenticated} = 0;
    print "CHILD $heap->{session}: Sent challenge. Hint: "
      . md5_hex( $secret . $challenge ) . "\n"
      if $debug;
}

sub child_stop {
    print "CHILD $_[HEAP]->{session}: Stopped.\n";
}

sub child_flush {
    my ( $heap, $socket ) = @_[ HEAP, ARG0 ];
    if ( $heap->{shutdown} ) {
        print "CHILD $heap->{session}: terminating.\n";
        delete $heap->{readwrite};
    }

    #print "CHILD $heap->{session}: FlushEvent.\n";
}

sub child_input {
    my ( $kernel, $heap, $data ) = @_[ KERNEL, HEAP, ARG0 ];
    my $rw = $_[HEAP]->{readwrite};

    print "CHILD $heap->{session}: Got input from peer: $data\n" if $debug;

    doauth( $heap, $data ) or return;

    $_ = $data;

    my $ip_regexp = qr/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/;

    if (/^add ($ip_regexp) (\d+)/i) {
        cmdauth( $heap, $data ) or return;
        my ( $ip, $class ) = ( $1, $2 );
        print "ADD $ip, $class\n";
        add_host( $kernel, $heap, $ip, $class );

        #exec_shell($heap, $addsh, $ip, $mac);
        #$rw->put("+OK Added");

    }
    elsif (/^del ($ip_regexp)/i) {
        cmdauth( $heap, $data ) or return;
        my $ip  = $1;
        my $mac = $clients{$ip};

        $rw->put("-ERR Client not found") and return unless defined $mac;

        print "DEL $ip, $mac\n";

        del_host( $heap, $ip, $mac );

        $rw->put("+OK Deleted");

    }
    elsif (/^reset/i) {
        cmdauth( $heap, $data ) or return;
        print "RESET\n";
        exec_shell( $heap, $resetsh );
        $rw->put("+OK Resetting firewall");

    }
    elsif (/^status/i) {
        cmdauth( $heap, $data ) or return;
        print_status($rw);
        print "STATUS\n";
        $rw->put("+OK End of status report");

    }
    elsif (/^quit/i) {
        $heap->{shutdown} = 1;
        $rw->put("+OK Bye");

    }
    elsif (/^help/i) {
        $rw->put("Valid commands:");
        $rw->put("  ADD <ip> <class> <auth>");
        $rw->put("  DEL <ip> <auth>");
        $rw->put("  RESET <auth>");
        $rw->put("  STATUS <auth>");
        $rw->put("  help");
        $rw->put("  quit");

    }
    else {
        $rw->put("-ERR invalid command or syntax. Try 'help'");
    }

}

sub child_done {
    delete $_[HEAP]->{readwrite};
    print "CHILD: disconnected from ", $_[HEAP]->{peername}, ".\n";
}

sub child_error {
    my ( $function, $error ) = @_[ ARG0, ARG2 ];

    delete $_[HEAP]->{readwrite};
    print "CHILD: call to $function() failed: $error.\n" if $error;
}

sub add_host {
    my ( $kernel, $heap, $ip, $class ) = @_;

    my $mac = getmac($ip);

    if ( defined $mac ) {

        print "Adding $ip, $mac\n";
        $clients{$ip} = $mac;
        exec_shell( $heap, $addsh, $ip, $mac, $class );

        add_pinger( $ip, $mac ) if $ping;

        $heap->{readwrite}->put("+OK Added");

    }
    else {

        $heap->{add}->{class}->{$ip} = $class;

        $kernel->post( pinger => ping => pong => $ip );

        print
"Spawnataanpa sitten monimutkaisempia rosesseja kerta mäkkiä ei saatu suoraan.\n"
          if $debug;
    }
}

sub del_host {
    my ( $heap, $ip, $mac ) = @_;

    delete $clients{$ip} and kill_pinger( $pingers{$ip} )
      if $clients{$ip} eq $mac;

    print "Deleting $ip, $mac\n";
    exec_shell( $heap, $delsh, $ip, $mac );
}

sub print_status {
    my $rw = shift;

    $rw->put("Settings:");
    $rw->put("DEBUG=$debug RESET=$reset");
    $rw->put(
        "PINGER=$ping PING_INTERVAL=$ping_interval PING_TIMEOUT=$ping_timeout");
    $rw->put("Connected clients:");

    foreach ( keys %clients ) {
        my $ip = $_;
        $rw->put("$ip\t$clients{$ip}");
    }

}

sub got_pong_arp {
    my ( $request_packet, $response_packet, $heap ) = @_[ ARG0, ARG1, HEAP ];
    my ( $request_address, $request_timeout, $request_time ) =
      @{$request_packet};
    my ( $response_address, $roundtrip_time, $reply_time ) =
      @{$response_packet};
    my $ip = $request_address;

    return if $heap->{add}->{added}->{$ip};
    return if $heap->{got_arp_pong};

    my $mac = getmac($ip);

    if ( defined $mac ) {

        print "(PONG) Adding $ip, $mac\n";

        $heap->{add}->{added}->{$ip} = 1;
        $clients{$ip} = $mac;
        exec_shell( $heap, $addsh, $ip, $mac, $heap->{add}->{class}->{$ip} );
        add_pinger( $ip, $mac ) if $ping;
        $heap->{readwrite}->put("+OK Added");

    }
    else {
        $heap->{readwrite}->put("-ERR Failed to get mac address");
        print "Failed to get mac address by pinging $ip\n";
    }
    $heap->{got_arp_pong} = 1;
}

sub exec_shell {
    my $heap = shift;
    my $cmd  = shift;

    $heap->{job} = POE::Wheel::Run->new(
        Program      => $cmd,
        ProgramArgs  => \@_,
        StdioFilter  => POE::Filter::Line->new(),
        StderrFilter => POE::Filter::Line->new(),

        # StdoutEvent  => "got_job_stdout",
        StderrEvent => "got_job_stderr",
        CloseEvent  => "got_job_close",
    );

    print "CHILD $heap->{session}: Job ", $heap->{job}->PID, " started.\n"
      if $debug;

}

sub add_pinger {
    my ( $ip, $mac ) = @_;

    kill_pinger( $pingers{$ip} ) if defined $pingers{$ip};

    $pingers{$ip} = POE::Session->create(
        inline_states => {
            _start => \&pinger_start,
            _stop  => \&pinger_stop,
            ping   => \&pinger_ping,
            pong   => \&got_pong_pinger,
            clear  => \&pinger_clear,
        },

        args => [ $ip, $mac ],

    );

    $poe_kernel->detach_child( $pingers{$ip} );

}

sub kill_pinger {
    my $pinger = shift;
    $poe_kernel->post( $pinger, "clear" );
}

sub pinger_clear {

    # Clear upcoming ping event
    $_[KERNEL]->delay("ping");
}

sub pinger_start {
    my ( $kernel, $heap, $ip, $mac ) = @_[ KERNEL, HEAP, ARG0, ARG1 ];

    $heap->{ip}  = $ip;
    $heap->{mac} = $mac;

    $heap->{use_arp_cache}      = 0;
    $heap->{use_arp_cache_lock} = 0;
    $heap->{unreplied}          = 0;

    print "Pinger start, $ip\n" if $debug;
    $kernel->delay( "ping", $ping_interval );
}

sub pinger_stop {
    my $heap = $_[HEAP];
    print "Pinger stop ($heap->{ip})\n" if $debug;
    delete $pingers{ $heap->{ip} } if $pingers{ $heap->{ip} } eq $_[SESSION];
}

sub pinger_ping {
    my ( $kernel, $heap ) = @_[ KERNEL, HEAP ];
    my $gotmac;

    if ( defined $heap->{got_reply} and !$heap->{got_reply} ) {
        $heap->{unreplied}++;
        print "No reply from $heap->{ip} ($heap->{unreplied})\n" if $debug;
    }

    if ( $heap->{unreplied} > 3 ) {
        del_host( $heap, $heap->{ip}, $heap->{mac} );
        print "Dropping host $heap->{ip}\n";
        return;
    }

    $gotmac = getmac( $heap->{ip} ) if $heap->{use_arp_cache};
    if ( defined $gotmac and $gotmac eq $heap->{mac} ) {
        print "Got mac from cache ($heap->{ip})\n" if $debug;
        $heap->{got_reply} = 1;
        $heap->{unreplied} = 0;

    }
    else {
        $heap->{got_reply} = 0;
        $kernel->post( pinger => ping => pong => $heap->{ip} );
    }

    $kernel->delay( "ping", $ping_interval );
}

sub got_pong_pinger {
    my ( $kernel, $heap, $request_packet, $response_packet ) =
      @_[ KERNEL, HEAP, ARG0, ARG1 ];
    my ( $request_address, $request_timeout, $request_time ) =
      @{$request_packet};
    my ( $response_address, $roundtrip_time, $reply_time ) =
      @{$response_packet};
    my $ip = $request_address;

    return if $heap->{got_reply};
    unless ( defined $response_address ) {
        print "Timeout pinging $ip\n" if $debug;

        if ( !$heap->{use_arp_cache_lock} ) {
            $heap->{use_arp_cache_lock} = 1;
            $heap->{use_arp_cache}      = 1;
        }

        return;
    }

    print "Got pong from $response_address ($ip expected).\n" if $debug;

    my $gotmac = getmac($ip);

    if ( defined $gotmac and $gotmac eq $heap->{mac} ) {
        $heap->{got_reply} = 1;
        $heap->{unreplied} = 0;
    }

    if ( !$heap->{use_arp_cache_lock} ) {
        $heap->{use_arp_cache_lock} = 1;
        $heap->{use_arp_cache}      = 0;
    }
}

sub got_job_stderr {
    my $heap = $_[HEAP];
    print "CHILD $heap->{session}: Job ", $heap->{job}->PID,
      " Error: $_[ARG0]\n";
}

sub got_job_close {
    my $heap = $_[HEAP];
    print "CHILD $heap->{session}: Job ", $heap->{job}->PID, " finished.\n"
      if $debug;
    delete $heap->{job};
}

sub doauth ($$) {
    my $heap = shift;
    my $data = shift;

    return 1 if $heap->{authenticated};

    if ( authenticate( $data, $heap->{challenge} ) ) {

        $heap->{readwrite}->put("+OK Authenticated");
        print "CHILD $heap->{session}: Authenticated successfully\n" if $debug;

        $heap->{authenticated} = 1;

    }
    else {
        $heap->{readwrite}->put("-ERR Invalid credintentials");
        print "CHILD $heap->{session}: Invalid Credintentials\n";

        $heap->{shutdown} = 1;
    }

    return 0;

}

sub cmdauth($$) {
    my $heap = shift;
    my $data = shift;

    return 1 if verify_signature( $data, $heap->{challenge} );

    $heap->{readwrite}->put("-ERR Invalid signature");
    print "CHILD $heap->{session}: Invalid signature\n";
    return undef;
}

sub verify_signature($$) {
    my $input = shift;
    $input =~ /(.*?) ([0-9a-f]{32})/ or return undef;
    my ( $command, $sign ) = ( $1, $2 );

    my $chall = shift;

    print "Command: '$command' Hint: "
      . md5_hex( $secret, $chall, $command ) . "\n"
      if $debug;
    return 1 if $sign eq md5_hex $secret, $chall, $command;

    return undef;
}

sub authenticate($$) {
    my $input = shift;
    my $chall = shift;

    return 1 if $input eq md5_hex $secret. $chall;

    return undef;
}

sub rand_md5 {
    return md5_hex( time . rand 1000000 );
}

sub print_hash($) {
    my $hash = shift;
    print "Hash{$_}=$hash->{$_}\n" foreach keys %$hash;

}

sub getmac ($) {
    my $ip = shift;
    my $fp;
    my $mac;

    open $fp, "</proc/net/arp" or return undef;

    while (<$fp>) {
        next unless ( /^($ip)\s+0x1\s+0x2\b/ and $1 eq $ip );
        /([0-9a-fA-F:]{17})/ and $mac = $1 and last;
    }

    close $fp;

    return undef if !defined $mac or $mac eq "00:00:00:00:00:00";

    return $mac;
}

