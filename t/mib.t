#!./perl

# Written by John Stoffel (jfs@fluent.com) - 10/13/1997

BEGIN {
    unless(grep /blib/, @INC) {
        chdir 't' if -d 't';
        @INC = '../lib' if -d '../lib';
    }
}

use SNMP;

$SNMP::verbose = 0;
$n = 3;  # Number of tests to run

print "1..$n\n";
if ($n == 0) { exit 0; } else { $n = 1; }

my $junk_oid = ".1.3.6.1.2.1.1.1.1.1.1";
my $oid = '.1.3.6.1.2.1.1.1';
my $name = 'sysDescr';
my $junk_name = 'fooDescr';
my $mib_file = 't/mib.txt';
my $junk_mib_file = 'mib.txt';

######################################################################
# See if we can find a mib to use, return of 0 means the file wasn't
# found or isn't readable. 

$res = SNMP::setMib($junk_mib_file,1);
printf "%s %d\n", (!$res) ? "ok" :"not ok", $n++;

######################################################################
# Now we give the right name

$res = SNMP::setMib($mib_file,1);
printf "%s %d\n", ($res) ? "ok" :"not ok", $n++;

######################################################################
# See if we can find a mib to use

$res = SNMP::setMib($mib_file,0);
printf "%s %d\n", ($res) ? "ok" :"not ok", $n++;



