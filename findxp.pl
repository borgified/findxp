#!/usr/bin/env perl

use Net::LDAPS;
use Net::LDAP::Control::Paged;
use Net::LDAP::Constant qw( LDAP_CONTROL_PAGED );
use POSIX qw(strftime);

#my %config = do '/secret/ingres.config';
#my %config = do '/secret/actian.config';
my %config = do '/secret/versant.config';
#my %config = do '/secret/pervasive.config';


my($ldap) = Net::LDAPS->new($config{'host'}) or die "Can't bind to ldap: $!\n";

my $mesg=$ldap->bind(
	dn      => "$config{'username'}",
	password => "$config{'password'}",
);  

if($mesg->error eq 'Success'){
}else{  
	print "check AD credentials\n";
	print $mesg->error;
}

my $page = Net::LDAP::Control::Paged->new( size => 100 );

my @args = (
	base     => $config{'base'},
	scope    => "subtree",
	filter   => "(samAccountType=805306369)",
	# callback => \&process_entry, # Call this sub for each entry
	control  => [ $page ],
);

my $cookie;

sub convert {

	my $time = shift @_;
	my $output;

	if($time == 0){
		$output = "n/a";
	}else{
		#http://www.perlmonks.org/?node_id=600396
		#using 11676009600 instead of 11644473600
		#http://meinit.nl/convert-active-directory-lastlogon-time-to-unix-readable-time
		$output = POSIX::strftime( "%Y-%m-%d", localtime(($time/10000000)-11676009600) );
	}

	return $output;
}


while (1) {
	# Perform search
	my $mesg = $ldap->search( @args );

	die "LDAP error: server says ",$mesg->error,"\n" if $mesg->code;

	# Only continue on LDAP_SUCCESS
	$mesg->code  and last;

	my $count=1;

	foreach ($mesg->entries) {
		my $os=$_->get_value('operatingSystem');

		#we use lastlogontimestamp instead of lastlogon because
		#http://kpytko.pl/2012/07/30/lastlogon-vs-lastlogontimestamp/
		my $lastlogonts=$_->get_value('lastLogonTimestamp');
		my $distinguishedName=$_->get_value('distinguishedName');
		my $dnshostname =$_->get_value('dNSHostName');
		#my $name = $_->get_value('name');

		my $human_readable_ts=&convert($lastlogonts);

		print "'$os','$human_readable_ts','$dnshostname','$distinguishedName'\n";
		#enable next line for debugging (limits to 40 loops)
#		exit if $count > 39;
		$count++
	}

	my($resp)  = $mesg->control( LDAP_CONTROL_PAGED )  or last;
	$cookie    = $resp->cookie;

	# Only continue if cookie is nonempty (= we're not done)
	last  if (!defined($cookie) || !length($cookie));

	# Set cookie in paged control
	$page->cookie($cookie);
}

if (defined($cookie) && (length($cookie))) {
	# We had an abnormal exit, so let the server know we do not want any more
	$page->cookie($cookie);
	$page->size(0);
	$ldap->search( @args );
}


