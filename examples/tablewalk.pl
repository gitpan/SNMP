$session = new SNMP::Session ( DestHost => $host );

#test snmpwalk of a single table
print "table walk test(getnext)\nipAddrEntry Table:\n";
for ($vars=new SNMP::VarList([ipAdEntAddr],[ipAdEntIfIndex],[ipAdEntNetMask]),
     @vals = $session->getnext($vars);
     $vars->[0]->tag =~ /ipAdEntAddr/ and # still in table
     not $session->{ErrorStr}; # and not end of mib or other error
     @vals = $session->getnext($vars)) {

     print "   $vals[0]/$vals[2] ($vals[1])\n";

}
