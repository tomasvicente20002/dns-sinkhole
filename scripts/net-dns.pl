use Net::DNS;

my $res   = Net::DNS::Resolver->new (
	nameservers => [qw(localhost)],
	recurse => 0,
	debug => 1,
	port => 53,

);
my $query = $res->query("facebook.com");

if ($query) {
	foreach my $rr ($query->answer) {
		next unless $rr->type eq "A";
			print $rr->address, "\n";
	}
} else {
   	warn "query failed: ", $res->errorstring, "\n";
}

