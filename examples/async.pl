use SNMP;
package Callback; 
sub new { $type = shift; $self = shift; bless $self, $type;} 
sub DESTROY { print "Callback::DESTROY($_[0])\n";} 
1;
package main;

$SNMP::auto_init_mib = 0; 
$sess = new SNMP::Session(); 
$cb = new Callback([\&poller, $sess]); 
$i = 1; 

sub poller {  
   $ps = `ps -u$$`; 
   $cur = (split(" ",$ps))[15]; 
   print $cur - $last," ($cur) [$i]\n"; 
   ++$i; 
   $last = $cur; 
   my $cb = new Callback([\&poller, $_[0]]);
   $_[0]->set($_[1], $cb);
} 

$sess->set([[".1.3.6.1.2.1.1.3.0"]], $cb); 

SNMP::MainLoop();
