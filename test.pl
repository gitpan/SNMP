use SNMP 1.7;

$host = shift;
unless ($host) {
  $| = 1;  print "enter SNMP host address: "; $| = 0;
  chomp($host = <STDIN>);
}

$SNMP::verbose = 1; # right now only echos mib load progress, more later

# $SNMP::auto_init_mib = 0; # set to one for programmer control of mib loading
                          # see SNMP::setMib below

print "\nBegin test script, SNMP Module version $SNMP::VERSION\n";
print "Automatic Mib Initialization: ",
       ($SNMP::auto_init_mib ? 'ENABLED' : 'DISABLED'), "\n";
print "Verbose Output: ",
       ($SNMP::verbose ? 'ENABLED' : 'DISABLED'), "\n\n";

# SNMP::setMib('mib.txt'); # load mib from specified file, pass second arg
                           # non-zero to force mib change from prev. load

# create new Session

$session = new SNMP::Session ( DestHost => $host );

print "\n\$session->\{DestHost\}  = $session->{DestHost}\n",
      "\$session->\{DestAddr\}  = $session->{DestAddr}\n", 
      "\$session->\{Version\}   = $session->{Version}\n", 
      "\$session->\{Community\} = $session->{Community}\n\n";

$host = $session->{DestAddr}; # make sure host is dotted decimal ip addr

# create list of varbinds for GETS, val field can be null or omitted
$vars = new SNMP::VarList (
			   ['sysDescr', '0', ''],
			   ['sysContact', '0'],
			   ['sysName', '0'],
			   ['sysLocation', '0'],
			   ['sysServices', '0'],
			   ['ifNumber', '0'],
			   ['ifDescr', '1'],
			   ['ifSpeed', '1'],
			  );

# GET tests
print "Doing GET test.\n";
@ret = $session->get($vars);
print "get test (return vals):\n(1)$ret[0]\n(2)$ret[1]\n(3)$ret[2]\n(4)$ret[3]\n(5)$ret[4]\n(6)$ret[5]\n(7)$ret[6]\n(8)$ret[7]\n\n" if @ret;
print "ErrorStr =>\"$session->{ErrorStr}\", ErrorNum => \"$session->{ErrorNum}\"\n" unless @ret;

print "get test (varlist):\n";
foreach $var (@{$vars}) {
  $name = $var->tag;
  $iid = $var->iid;
  $val = $var->val || '';
  $type = $var->type || '';
  print "$name.$iid = $val($type)\n";
}
print "\n";

# setup for SET test -  make sure to change things back the way they were!
print "Doing SET test.\n";
$old = $session->get('sysContact.0');
print "got sys contact = $old\nSetting new sys contact...\n";

$result = $session->set('sysContact.0', 'gmarzot@baynetworks.com');

$new = $session->get('sysContact.0');
print "got sys contact = $new\nre-setting sys contact...\n";

$result = $session->set('sysContact.0', $old);

$newold = $session->get('sysContact.0');
print "got sys contact = $newold (original $old)\n\n";

# Test the "Powerful GetNext Operation"
print "Doing GET-NEXT test.\n";
@result = $session->getnext($vars);
print "getnext(return vals): @result\n\n";

print "getnext test (varlist):\n";
foreach $var (@{$vars}) {
  $name = $var->tag;
  $iid = $var->iid;
  $val = $var->val || '';
  $type = $var->type || '';
  print "$name.$iid = $val($type)\n";
}
print "\n";

$val = $session->getnext('sysDescr.0');
print "sysObjectID.0 = $val\n\n";

#test snmpwalk of a single table
print "table walk test(getnext)\nipAddrEntry Table:\n";
for ($vars=new SNMP::VarList([ipAdEntAddr],[ipAdEntIfIndex],[ipAdEntNetMask]),
     @vals = $session->getnext($vars);
     $vars->[0]->tag =~ /ipAdEntAddr/ and
     not $session->{ErrorStr};
     @vals = $session->getnext($vars)) {
     
     print "   $vals[0]/$vals[2] ($vals[1])\n";

}

print "\nDoing type and translation tests:\n\n";
$type = SNMP::getType('foo');
print "type obj foo = ", (defined($type) ? "\"$type\"" :'"undef"'),"\n";
$obj_tag = 'sysDescr';
print "tag = $obj_tag\n";
$oid = SNMP::translateObj($obj_tag);
$type = SNMP::getType($obj_tag);
print "oid = $oid, type = $type\n";
$obj_tag = SNMP::translateObj($oid);
print "tag = $obj_tag\n";
$oid = SNMP::translateObj("$obj_tag.0");
print "oid = $oid\n";
$tag_iid = SNMP::translateObj($oid);
print "tag.iid = $tag_iid\n";


 
