use SNMP;

$SNMP::auto_init_mib = 0; 

$sess = new SNMP::Session(); 

sub poller {  
   print $_[1][0]->tag, " = ", $_[1][0]->val, "\n";
   if ($i++>500) {exit(0)};
   $_[0]->get($_[1], [\&poller, $_[0]]);
} 

$sess->get([[".1.3.6.1.2.1.1.3.0"]], [\&poller, $sess]); 

SNMP::MainLoop();
