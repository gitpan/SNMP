#!./perl

# Written by John Stoffel (jfs@fluent.com) - 10/18/1997

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

use SNMP 1.7;

my($host,$comm);
if (-f 'host') {
   ($host, $comm) = split(' ',`cat host`);
}
$host ||= 'localhost';
$comm ||= 'private';

$SNMP::verbose = 0;
$n = 14;  # Number of tests to run

print "1..$n\n";
if ($n == 0) { exit 0; } else { $n = 1; }

my $junk_oid = ".1.3.6.1.2.1.1.1.1.1.1";
my $oid = '.1.3.6.1.2.1.1.1';
my $junk_name = 'fooDescr';
my $junk_host = 'no.host.here';
my $name = "gmarzot\@baynetworks.com";

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

######################################################################
# Create a bogus session, undef means the host can't be found.
my $s2 = new SNMP::Session ( DestHost => $junk_host );
printf "%s %d\n", !defined($s2) ? "ok" :"not ok", $n++;

######################################################################
# Fire up a session.
my $s1 = new SNMP::Session ( DestHost => $host, Community => $comm);
printf "%s %d\n", ($s1) ? "ok" :"not ok", $n++;

######################################################################
# Get the standard Vars and check that we got some back
@ret = $s1->get($vars);
printf "%s %d\n", (@ret) ? "ok" :"not ok", $n++;

######################################################################
# Check that we got back the number we asked for.
printf "%s %d\n", ($#ret == $#{$vars}) ? "ok" :"not ok", $n++;

######################################################################
# Start of Set tests.
######################################################################
# Save the original sysContact.0 name
$orig_name = $s1->get('sysContact.0');
printf "%s %d\n", defined($orig_name) ? "ok" :"not ok", $n++;
######################################################################
# Change to another name
my $res1 = $s1->set('sysContact.0', $name);
printf "%s %d\n", ($res1 == 0) ? "ok" :"not ok", $n++;

######################################################################
# Get the new name and make sure it matches
my $new = $s1->get('sysContact.0');
printf "%s %d\n", (defined($new) and $new eq $name) ? "ok" :"not ok", $n++;

######################################################################
# reset to the original value
$s1->set('sysContact.0',$orig_name);
printf "%s %d\n", ($s1->{ErrorInd} == 0) ? "ok" :"not ok", $n++;

######################################################################
# Try to change a read-only value
$s1->set('sysUpTime.0', 0);
printf "%s %d\n", ($s1->{ErrorInd} == 1) ? "ok" :"not ok", $n++;
######################################################################
# getnext tests
######################################################################
# We should get back sysDescr.0 here.
my $var = new SNMP::Varbind(['sysDescr']);
my $res2 = $s1->getnext($var);
printf "%s %d\n", ($var->tag eq 'sysDescr') ? "ok" :"not ok", $n++;
printf "%s %d\n", ($var->iid == 0) ? "ok" :"not ok", $n++;
printf "%s %d\n", ($var->val eq $res2) ? "ok" :"not ok", $n++;

######################################################################
# get the next one after that as well for a second check
my $res3 = $s1->getnext($var);
printf "%s %d\n", ($var->tag eq 'sysObjectID') ? "ok" :"not ok", $n++;
printf "%s %d\n", ($var->val eq $res3) ? "ok" :"not ok", $n++;
