use SNMP 1.6;

$host = shift;
unless ($host) {
  $| = 1;  print "enter SNMP host address: "; $| = 0;
  chomp($host = <STDIN>);
}

# $SNMP::auto_init_mib = 0;
print "\nBegin test script, SNMP Module version $SNMP::VERSION\n";
print "Automatic Mib Initialization: ",
       ($SNMP::auto_init_mib ? 'ENABLED' : 'DISABLED'), "\n\n";

# SNMP::setMib('mib.txt');

# create Session (will use host from command line if supplied)

$session = new SNMP::Session ( DestHost => $host, Community => 'public' );

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
print "get test (return vals):\n(1)$ret[0]\n(2)$ret[1]\n(3)$ret[2]\n(4)$ret[3]\n(5)$ret[4]\n(6)$ret[5]\n(7)$ret[6]\n(8)$ret[7]\n\n";

print "get test (varlist):\n";
foreach $var (@{$vars}) {
  $name = $var->[$SNMP::Varbind::tag_f];
  $iid = $var->[$SNMP::Varbind::iid_f];
  $val = $var->[$SNMP::Varbind::val_f] || '';
  print "$name.$iid = $val\n";
}
print "\n";

$ip = $session->get(['wfIpInterfaceMask', "$host.1"]);
print "get wfIpInterfaceMask(anon array ref arg): ",
      join('.', unpack("C4",$ip)),", $ip(raw)\n\n";

$ip = $session->get("wfIpInterfaceMask.$host.1");
print "get wfIpInterfaceMask(scalar arg): ",
      join('.',unpack("C4", $ip)),", $ip(raw)\n\n";

$oct = $session->get(['wfNodeProtoMap', '0']);
print "get wfNodeProtoMap(octet string): ",
      join(' ',  '0x', map {sprintf "%02X", $_} unpack("C*", $oct)), " \n\n";

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
  $name = $var->[$SNMP::Varbind::tag_f];
  $iid = $var->[$SNMP::Varbind::iid_f];
  $val = $var->[$SNMP::Varbind::val_f];
  if ($name eq 'sysObjectID' ) {
    print "$name.$iid = ", join('.', unpack("I*", $val)), "\n";
  } else {
    print "$name.$iid = $val\n";
  }
}
print "\n";

$val = $session->getnext('sysDescr.0');

print "sysObjectID.0 = ", join('.', unpack("I*", $val)), "\n\n";

$val = SNMP::translateObj('sysDescr');
print "val = $val\n"; $val =~ s/^\.//;
$val = SNMP::translateObj($val);
print "val = $val\n";
$val = SNMP::translateObj('sysDescr.0');
print "val = $val\n";
$val = SNMP::translateObj($val);
print "val = $val\n";




 
