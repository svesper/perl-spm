#!/usr/bin/perl

# perl-spm
# Perl SCGI Process Manager - SCGI application server
# Author: Copyright 2021-2022, S.Vesper (https://github.com/svesper/)
# License: GPL

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

use strict;
use warnings;
use POSIX qw(:signal_h setsid WNOHANG);
use IO::File;
use IO::Socket;
use IO::Select;
use Fcntl ':flock';

our $VERSION = 1.36;


use constant LOG_LEVEL		=> 2;			# 1=ERROR, 2=INFO, 3=DEBUG | LL >0 = ERROR; LL >1 = INFO; LL >2 = DEBUG
use constant LOG_IP             => 2;                   # 0=no IP logging, 1=anonymous IP, 2=full IP log
use constant LOCAL_PORT		=> 9004;		# default 9004
use constant LOCAL_ADDR		=> 'localhost';
use constant RUN_USER		=> 'www-data';
use constant RUN_GROUP		=> 'www-data';
use constant SERVER_MAX_PROC	=> 6;			# Number of max servers process, can be in total MAX_PROC + MIN_IDLE
use constant SERVER_MIN_IDLE	=> 2;			# Number of idle servers and initial servers to start
use constant PROGRAM_NAME	=> 'perl-spm';
use constant PIDFILE		=> '/tmp/'.PROGRAM_NAME.'.pid';
use constant LOGFILE		=> '/var/log/'.PROGRAM_NAME.'.log';
use constant BUFSIZE		=> 4096;		# buffersize 4k (4096) or 8k (8192) like pagesize
use constant PIPE_BUF		=> 4096;		# till 4096 bytes, pipe writes are atomic (on linux)


$0 = PROGRAM_NAME;

my $SRV_PID;						# server pid
my $SRV_EXIT	= 0;  					# true if exit server
my $SRV_CNT	= 0;					# No. of forked server process
my $SRV_IDL	= 0;					# No. of forked server process
my %SRV_PROC	= ();					# process status hash


open(my $FH, '>>', LOGFILE) or die "$0 [$$]: can not open logfile ".LOGFILE." - $!!";
	$FH->autoflush(1);

sub _log {
        my $msg = shift;
        my $timestamp = localtime;
        flock($FH,LOCK_EX);
        print $FH "$timestamp : $msg \n";
        flock($FH,LOCK_UN);
}


$SIG{INT} = $SIG{TERM} = sub { $SRV_EXIT++ };

my $socket = IO::Socket::INET->new(
			LocalAddr => LOCAL_ADDR, 
			LocalPort => LOCAL_PORT,
			Listen	  => SOMAXCONN,		# socket maximum number of queued connections /proc/sys/net/core/somaxconn
			ReuseAddr => 1			# true value set SO_REUSEADDR option on socket to avoid "address in use" errors on restart
			) or die "Can't create listen socket: $!"; 
				

# unidirectional pipes for child to parent communication
pipe(my $PIPE_READ, my $PIPE_WRITE) or die "pipe creation failed: $!\n";
$PIPE_WRITE->autoflush(1);

my $IN = IO::Select->new($PIPE_READ);

# initialize & daemonize server
init_server();

# prefork child process - inherited everything until here like the SIGINT handler 
prefork() for (1 .. SERVER_MIN_IDLE);

# main loop
while (!$SRV_EXIT) {

	# got a inter process communication message from child process via pipe
	if ($IN->can_read) {
		my $ipc_msg;
		
		# Prevent a pipe read deadlock. sysread will wait if no data is in pipe. reading from pipes emptys them.
 		# use fix/static 4k pipe buffer which allows atomic writes
		my $bytes = sysread($PIPE_READ, $ipc_msg, PIPE_BUF);

		# test sysread for undef on error or 0 for zero data
		if (!defined $bytes || $bytes == 0) {
			next;
		}

		#_log("child msg main loop: $message");
		foreach my $msg ( split("\n", $ipc_msg) ) {
			my ($pid,$status) = $msg =~ /^([0-9]+):(.+)$/;
			
			if ($status ne 'exit') {
				$SRV_PROC{$pid} = $status;
		
				if ($status eq 'idle') {
					$SRV_IDL++;
				} elsif ($status eq 'active') {
					$SRV_IDL--;
				}
			} else {
				delete $SRV_PROC{$pid};
				$SRV_CNT--;
			}
		}
	}

	if (LOG_LEVEL >2) {
		my $msg;
		foreach my $key (sort keys %SRV_PROC) {
			$msg .= $key.'=>'.$SRV_PROC{$key}.' ';
		}
		_log("server process: $msg");
	}

		
	_log("SRV_CNT:$SRV_CNT - SRV_IDL:$SRV_IDL - idle server process target") if (LOG_LEVEL >2);

	# check total number of server process
	if($SRV_CNT < SERVER_MAX_PROC) {	
 		# create minimum number of idle server process
		if($SRV_IDL < SERVER_MIN_IDLE) {
			prefork() for (0 .. SERVER_MIN_IDLE-$SRV_IDL);
		}
	
	} else {
		# only 1 idle server left, adjust config
		if($SRV_IDL < 2) { 
			_log("SERVER_MAX_PROC limit of $SRV_CNT server reached and only $SRV_IDL idle server left. Increase SERVER_MAX_PROC.");
			my $msg;
			foreach my $key (sort keys %SRV_PROC) {
				$msg .= $key.'=>'.$SRV_PROC{$key}.' ';
			}
			_log("server process: $msg");
		}
	}
}

# SIGHUP received - exit
_log("SIGHUP received, stopping server") if (LOG_LEVEL >2);
killall_srvproc();

_log('Stopping SCGI server '.PROGRAM_NAME." ");
close($FH) or _log("Error closing logfile: $!"); # close logging filehandle
exit 0;

sub prefork {
  	my $signals = POSIX::SigSet->new(SIGINT,SIGCHLD,SIGTERM,SIGHUP);
  	sigprocmask(SIG_BLOCK,$signals);  				# block signals while forking
  	
	die("Can't fork: $!") unless defined (my $child = fork());	# wait on child proc
  	if ($child) {							# child pid to parent (child = pid of child)
    		$SRV_PROC{$child} = 'idle';
  	} else {							# child proc (child = 0)
    		$SIG{HUP} = $SIG{INT} = $SIG{CHLD} = $SIG{TERM} = 'DEFAULT';
  		$< = $>;  # set real UID to effective UID
  	}
  	
	sigprocmask(SIG_UNBLOCK,$signals);  				# unblock signals

	if ($child) { 				# child > 0 parent proc
		_log("preforking server[$child]") if (LOG_LEVEL >2);
		$SRV_CNT++;
	} else {
 		# only need write pipe
		close($PIPE_READ) or _log("Error closing read pipe: $!");
		init_connection($socket);	# child handles incoming connections
		_log("server[$$]: exit process") if (LOG_LEVEL >2);
		exit 0;                 	# exit child
	}
}

sub init_connection {
	my $socket = shift;
	my $lock   = IO::File->new(PIDFILE,O_RDONLY) or die "Can't open lock file: $!";
	my $hangup = 0;

	$SIG{HUP} = sub { $hangup++ };
	if ( !$hangup ) {
		syswrite($PIPE_WRITE, "$$:idle\n", PIPE_BUF);
		_log("server[$$]: idle") if (LOG_LEVEL >2);
		my $c;
		next unless eval {
			local $SIG{HUP} = sub { $hangup++; die };
			flock($lock,LOCK_EX);
			_log("server[$$]: accepting main socket connections") if (LOG_LEVEL >2);
			$c = $socket->accept;
			flock($lock,LOCK_UN);
		};
		syswrite($PIPE_WRITE, "$$:active\n", PIPE_BUF);
		_log("server[$$]: handle request") if (LOG_LEVEL >2);
		handle_connection($c);
		close($c);
	}
	_log("server[$$]: completed request") if (LOG_LEVEL >2);
	syswrite($PIPE_WRITE, "$$:exit\n", PIPE_BUF);
	close($socket);
	close($lock);
	close($PIPE_WRITE) or _log("Error closing write pipe: $!");
}

sub handle_connection {
	my $c = shift; 		# socket accept object
	$| = 1; 		# turn on autoflush	
	
	_log("server[$$]: connection handler called.") if (LOG_LEVEL >2);
			
	# read con request
	my $total_read 	= 0;
	my $buffer 	= '';

	# client request data from connection socket
	my $read = eval {
		local $SIG{ALRM} = sub { _log("server[$$]: connection timeout"); die "timeout\n"; };
		alarm (15);
		sysread($c , $buffer , BUFSIZE,  );
	};
	alarm(0);
	if (!defined($read)) { # connection timed out or empty request
		return; 
	}


	#
	# SCGI request
	#
	if ($buffer =~ m/^[0-9]+:/ ) {
		_log("SCGI Request.") if (LOG_LEVEL >2);


		#
		# SCGI Header
		#
	
		# get scgi request header length	
		my ($scgi_hdr_len) = $buffer =~ m|^([0-9]+):|;
	
		if ( !defined($scgi_hdr_len) ) {
			_log("malformed netstring length - closing connection");
			return;
		}
		_log("SCGI header length: $scgi_hdr_len") if (LOG_LEVEL >2);

		my $header_buffer_len = $scgi_hdr_len + length($scgi_hdr_len) + 2; # +2 is header ":" and body separator ","
		
		my $buf_len = length($buffer);
		if ( $buf_len < $header_buffer_len ) { 		# if request header was bigger than the buffer size, read the rest of the header
			_log("Request header bigger than buffer, reading rest of request.") if (LOG_LEVEL >2);
			if ( $read == BUFSIZE ) {		# real read bytes are equal bufsize, so buffer was full. Prevent buffer allocation attacks by just setting big header lengths on client requests.
				$read = eval {
					local $SIG{ALRM} = sub { _log("connection timeout(rebuffer request header)"); die "timeout\n"; };
					alarm (3);
					# read  from connection, to buffer, size header_leng minus buffer read, offset is buffer size (already read)
					sysread($c , $buffer , $header_buffer_len - $buf_len, $buf_len);
				};
				alarm(0);
				if ($@ =~ /timeout/) {		# check return value for: die "timeout\n"
					_log("Connection timeout");
					return;
				}
				_log("Req Header buf_len: ".length($buffer)) if (LOG_LEVEL >2);
			} else {
				_log("netstring length oversized, preventing malicious allocation.");
			}
		}
	
	
		#
		# SCGI Body
		#
		
		my ($content_length) = $buffer =~ m|CONTENT_LENGTH\x00([0-9]+)\x00|;
		_log("CONTENT_LENGTH: $content_length") if (LOG_LEVEL >2);
		
		my $body_buffer_len  = $header_buffer_len + $content_length;
		
		if ( length($buffer) < $body_buffer_len ) { 		# body was not in buffer, read the rest of the request
			_log("Request body bigger than buffer, reading rest of request body.") if (LOG_LEVEL >2);
			
			# read complete data to buffer
			while (length($buffer) < $body_buffer_len) {
				$read = eval {
					local $SIG{ALRM} = sub { _log("connection timeout(rebuffer request header)"); die "timeout\n"; };
					alarm (3);
					sysread($c, $buffer, BUFSIZE, length($buffer));
					# read all at once, no while loop needed then.
					# additional checks for content_length buffer allocation?
					# sysread($c , $buffer , $body_buffer_len - length($buffer), length($buffer));
				};
				alarm(0);
				if ($@ =~ /timeout/) {          	# check return value for: die "timeout\n"
					_log("Connection timeout");
					return;
   					last;
				}
			}
			_log("Done reading rest of request body.") if (LOG_LEVEL >2);
			_log("Complete Buffer length: ".length($buffer)."") if (LOG_LEVEL >2);
		}	
	
		scgi_request($c, $buffer, $header_buffer_len);	# put body in scgi_request sub? pass references does not workt for buffer and body
		undef($buffer);					# delete pointer, free memory of this object - if this is the 'original' variable

	#	
	# Other request types (like FCGI requests)
	#

	} else {
		_log("server[$$]: request type not supported.") if (LOG_LEVEL >0);
		if (LOG_LEVEL >2) {
			my $req = $buffer;
			   $req =~ s/\n//g;
			   $req =~ s/\r//g;
			_log("server[$$]: FCGI or other Request: \"$req\"");
		}

	} 

	#_log("End request");
	return;
}

sub scgi_request {
	my $c 			= shift;
	my $buffer 		= shift;
	my $header_buffer_len	= shift;
	
	# substr EXPR,OFFSET,LENGTH,REPLACEMENT
	# substr performance from start poistion (0) is ok, see https://docstore.mik.ua/orelly/perl/prog3/ch24_02.htm	
	my $header = substr($buffer, 0, $header_buffer_len, '');

	          
	_log("Header length: ".length($header)) if (LOG_LEVEL >2);
	_log("Body   length: ".length($buffer)) if (LOG_LEVEL >2);

	# remove header length from buffer string beginning
	$header =~ s/^([0-9]+)://;
	# remove body separator "," from header
	$header =~ s/,$//;
	
	# save request header to ENV hash
	local our %ENV = (); # clear environment
	my @hdarr = split(/\x00/, $header);
	for my $i (0 .. $#hdarr) {
		if ($i % 2) { next; }
		$ENV{$hdarr[$i]}=$hdarr[$i+1];	
	}

#	if( $ENV{'CONTENT_LENGTH'} eq '' ) {
#		$ENV{'CONTENT_LENGTH'} = 0;
#	}

        my $client_ip = '';

        if(LOG_IP == 0) {
                $client_ip = '-';
        } elsif (LOG_IP > 0) {
                if (defined $ENV{'HTTP_X_REAL_IP'}) {
                        $client_ip = $ENV{'HTTP_X_REAL_IP'};
                }
                elsif (defined $ENV{'HTTP_X_FORWARDED_FOR'}) {
                        $client_ip = $ENV{'HTTP_X_FORWARDED_FOR'};
                }
                elsif (defined $ENV{'REMOTE_ADDR'}) {
                        $client_ip = $ENV{'REMOTE_ADDR'};
                }

                if(LOG_IP == 1) {
                        my @ip = split(/\.|:/, $client_ip);
                        $client_ip = $ip[0].'.'.$ip[1];
                }
        }
	
	if(LOG_LEVEL >2) { 		# debug request header
		my $str;
		foreach my $key (keys %ENV) { 
			$str .= $key."->".$ENV{$key}." # ";
		}
		_log($str);
	}	

	# log client request to file
	_log('SCGI request host "'.$ENV{'HTTP_HOST'}.'", "'.$ENV{'REQUEST_METHOD'}.' '.$ENV{'REQUEST_URI'}.'", client "'.$client_ip.'"') if (LOG_LEVEL >1);

	#
	# body data / POSTDATA
	#
	if ( $ENV{'CONTENT_LENGTH'} != length($buffer) ) {	
		_log("Content length header does not match body length. CL: ".$ENV{'CONTENT_LENGTH'}." != Body: ".length($buffer)) if (LOG_LEVEL >0);
	}


	#
	# response
	#
      
	# configure $ENV{'SCRIPT_FILENAME'} in webserver:
	
	# 1. apache2
	# CONTEXT_DOCUMENT_ROOT->/var/www/apache # 
	# SCRIPT_NAME->/scgi/index.pl

	# 2. nginx
	# DOCUMENT_ROOT->/var/www/nginx 
	# SCRIPT_NAME->/scgi/index.cgi
		
	my $script = $ENV{'DOCUMENT_ROOT'}.$ENV{'SCRIPT_NAME'};

	# check if executable, non-zero size, readable
	if (-x -s -r -f $script) {
		my ($path) = $script =~ m/(.+)[\/\\].+$/;
		my $stdinFH;
		
		# create fake STDIN for bodydata / postdata processing
		open($stdinFH, "<", \$buffer) or _log("Could not open body data: $!");
		local *STDIN = $stdinFH;

		my $script_output;
		open(my $outputFH, '>', \$script_output) or die _log($@); 	# use typeglob reference \*$script_output?
		my $previousFH = select($outputFH); 				# change the default filehandle used by print() to outputFH and save previous filehandle to previousFH 

		my $do_return_value;
		{
			local $,;						# localize recent input filehandle
			chdir "$path" || _log("Error can't change to $path: $!");
			$do_return_value = do $script;
		}
		my $script_errors;						# errors returned by "do"ing script
		if ($@ && !defined($do_return_value)) { $script_errors .= 'cannot compile: "'.$@.'". '; }
		if ($! && !defined($do_return_value)) { $script_errors .= '"'.$!.'"'; }
		# if (!defined($do_return_value)) { $script_errors .= "Cannot run file"; } # simple return; in script would trigger this. eq return undef
                
		select($previousFH);						# reset print() default filehandle
		close($outputFH) or _log("Error closing outputFH: $!");
		close($stdinFH)  or _log("Error closing stdinFH: $!");

		print $c $script_output;
                
		if ($script_errors) {
			_log("Perl-SPM script errors, $script_errors in \"$script\"");
			#_log("Compile error: $@. Read file error: $!.");
	 	}
	
		undef($script_output);						# delete pointer and free memory of this object 

		## Do not try to free memory in processes. INCREASE RESPONSE TIME from 50ms to ~350ms
		## even spawning new childs each process only result in 60ms
		## try: %HASH = ();     # completely empty %HASH
		## and re-aply saved %INC values
		
		#if (defined($INC{'CGI.pm'})) {
		#	exit(0);		# exit this child process
		##	delete $INC{'CGI.pm'};	# works but very slow
		#}
		
		## undef($buffer); 	# unneccessary
		## exit(0);		# exit this child process and SCGI request

	# is directory
	} elsif ( -d $script ) {
			print $c return_error("Missing index file! File \"$script\" not found or index not defined. :(");
	
	} else {
		_log("$script not executable or readable or empty!") if (LOG_LEVEL >0);
		print $c return_error("File not found! Not executable or readable. :(");
	}

	undef($buffer);
	return; # ends connection?
}

sub return_error {
        my $err = shift;

	my $output;
	$output .= 'Status: 404 Not Found'."\r\n";
        $output .= 'Content-type: text/plain; charset=utf-8'."\r\n\r\n";
        $output .= '** 404 Not Found **'."\r\n\r\n";
        $output .= '> '.$err."\r\n\r\n";
        $output .= '_perl-spm_'."\r\n";

	return $output;
}

#
# Main process (Daemon)
#

sub init_server {
	_log('Starting SCGI server '.PROGRAM_NAME." v$VERSION");
	my $fh = open_pid_file(PIDFILE);
	
	# daemonize
	defined(my $pid = fork())	|| die "Can't fork: $!";
	exit 0 if $pid;    		# exit parent process, which gets pid of child returned;
	POSIX::setsid();     		# become session leader
	open(STDIN,  "<", "/dev/null")	|| die "Can’t redirect STDIN: $!";
	open(STDOUT, ">", "/dev/null")	|| die "Can’t redirect STDOUT: $!";
	open(STDERR, ">&", STDOUT)	|| die "Can't redirect STDERR: $!";
	chdir('/')			|| die "Can't chdir daemon: $!";     # change working directory
	umask(0);            		# forget file mode creation mask
	$ENV{PATH} = '/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin';
	delete @ENV{'IFS', 'CDPATH', 'ENV', 'BASH_ENV'};
	$SIG{CHLD} = sub {
		# returns the pid of the deceased process, or -1 if there is no such child process. 
		# https://www.perl.com/article/fork-yeah-part-2/
		# https://perldoc.perl.org/functions/waitpid
		while ( (my $child = waitpid(-1, WNOHANG)) > 0) {
			_log("SIGCHLD received, waitpid removed process $child") if (LOG_LEVEL >2);
	    		delete $SRV_PROC{$child};
  		}
	};


	print $fh $$;
	close($fh) or _log("Error closing pidfile: $!");
	
	# drop privs
	my $uid = getpwnam(RUN_USER)  or die "Can't get uid for ".RUN_USER."\n";
	my $gid = getgrnam(RUN_GROUP) or die "Can't get gid for ".RUN_GROUP."\n";
	$) = "$gid $gid";
	$( = $gid;
	$> = $uid;   			# change the effective UID (but not the real UID)
	## drop permissions in setuid and/or setgid programs:
	## ($>, $)) = ($<, $();
	
	$SRV_PID = $$;
	return;
}

sub killall_srvproc {
  	kill TERM => keys %SRV_PROC;
  	# wait until all child proc exit
  	sleep while %SRV_PROC;
}

sub open_pid_file {
  	my $file = shift;
  	if (-e $file) {  # oops.  pid file already exists
    		my $fh = IO::File->new($file) || return;
    		my $pid = <$fh>;
		# check id pid is number
    		die "Invalid PID file" unless $pid =~ /^([0-9]+)$/;
		# check that the process is alive/exist. kill 0 returns true without actually terminating it.
    		die "Server already running with PID $1" if kill 0 => $1;
    		warn "Removing PID file for defunct server process $pid.\n";
    		die "Can't unlink PID file $file" unless -w $file && unlink $file;
  	}
	# https://perlmaven.com/possible-precedence-issue-with-control-flow-operator
  	return IO::File->new($file,O_WRONLY|O_CREAT|O_EXCL,0644) || die "Can't create $file: $!\n";
}

END { 
  	$> = $<;  # regain privileges
  	unlink PIDFILE if defined $SRV_PID and $$ == $SRV_PID 
}

1;
__END__
