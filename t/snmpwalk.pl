use SNMP 1.6;

$host = shift;
unless ($host) {
  $| = 1;  print "enter SNMP host address: "; $| = 0;
  chomp($host = <STDIN>);
}

$sess = new SNMP::Session(DestHost => $host);

$var = new SNMP::Varbind([]);

do {
  $val = $sess->getnext($var);
  print "$var->[$SNMP::Varbind::tag_f].$var->[$SNMP::Varbind::iid_f] = $var->[$SNMP::Varbind::val_f] ($sess->{ErrorStr}:$sess->{ErrorNum})\n";
  open(PS,"ps -u$$|") || die;
  $size = (split(' ',(<PS>)[1]))[4];
  print "size = $size\n";
} until ($sess->{ErrorStr});
