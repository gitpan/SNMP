#!./perl

# Written by John Stoffel (jfs@fluent.com) - 10/13/1997

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

use SNMP 1.7;
SNMP::initMib();

$SNMP::verbose = 0;
$| = 1;
my $n = 7;  # Number of tests to run

print "1..$n\n";
if ($n == 0) { exit 0; } else { $n = 1; }

my $junk_oid = ".1.3.6.1.2.1.1.1.1.1.1";
my $oid = '.1.3.6.1.2.1.1.1';
my $name = 'sysDescr';
my $junk_name = 'fooDescr';

######################################################################
# Garbage names return Undef.

my $type1 = SNMP::getType($junk_name);
printf "%s %d\n", (!defined($type1)) ? "ok" :"not ok", $n++;

######################################################################
# For now, OIDs don't have a type.  Need to update getType()

my $type2 = SNMP::getType($oid);
printf "%s %d\n", (!defined($type2)) ? "ok" :"not ok", $n++;

######################################################################
# This tests that sysDescr returns a valid type.

my $type3 = SNMP::getType($name);
printf "%s %d\n", defined($type3) ? "ok" :"not ok", $n++;

######################################################################
# Translation tests from Name -> oid -> Name
######################################################################
# name -> OID
$oid_tag = SNMP::translateObj($name);
printf "%s %d\n", ($oid eq $oid_tag) ? "ok" :"not ok", $n++;

######################################################################
# bad name != OID

$oid_tag = '';
$oid_tag = SNMP::translateObj($junk_name);
printf "%s %d\n", ($oid ne $oid_tag) ? "ok" :"not ok", $n++;
######################################################################
# OID -> name

$name_tag = SNMP::translateObj($oid);
printf "%s %d\n", ($name eq $name_tag) ? "ok" :"not ok", $n++;

######################################################################
# bad OID -> Name

$name_tag = SNMP::translateObj($junk_oid);
printf "%s %d\n", ($name ne $name_tag) ? "ok" :"not ok", $n++;




