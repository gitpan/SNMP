use ExtUtils::MakeMaker;
require 5;
use Config;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

%MakeParams = InitMakeParams();

WriteMakefile(%MakeParams);

GetTestHost();

sub InitMakeParams {
my %Params = (
    NAME         => 'SNMP',
    dist         => { SUFFIX => "gz", COMPRESS => "gzip -9f"},
    MAN3PODS     => ' ',  # Pods will be built by installman.
    XSPROTOARG   => '-noprototypes', 	# XXX remove later?
    VERSION_FROM => 'SNMP.pm',

	    );
my $snmp_lib, $snmp_llib, $sep;
if ($Config{'osname'} eq 'MSWin32') {
    $snmp_lib = 'libsnmp.dll';
    $snmp_llib = 'libsnmp';
    $sep = '\\';
} else {
    $snmp_lib = 'libsnmp.a';
    $snmp_llib = 'snmp';
    $sep = '/';
}
my $inc_path1 = "${sep}usr${sep}include";
my $inc_path2 = "${sep}usr${sep}local${sep}include";
my $lib_path1 = "${sep}usr${sep}lib";
my $lib_path2 = "${sep}usr${sep}local${sep}lib";

my @IncludeFiles = qw[asn1.h mib.h parse.h snmp.h snmp_api.h 
		      snmp_client.h snmp_impl.h mib.h];

my @IncludeDirs = ($inc_path1, $inc_path2);

my $IncludeDir = find_files(\@IncludeFiles,\@IncludeDirs) ||
    prompt("Where are the $snmp_lib include files?","$inc_path2");

my @LibDirs = ($lib_path1, $lib_path2);

my $LibDir = find_files(["$snmp_lib"],\@LibDirs) ||
	prompt("Where is $snmp_lib installed?","$lib_path2");

   @IncludeFiles = map {"$IncludeDir$sep$_";} @IncludeFiles;
   $Params{LIBS} = "-L$LibDir -l$snmp_llib";
   $Params{INC}  = "-I$IncludeDir";
   $Params{H}    = \@IncludeFiles;
   return(%Params);
}

sub find_files {
    my($f,$d) = @_;
    my ($dir,$found,$file);
    for $dir (@$d){
	$found = 0;
	for $file (@$f) {
	    $found++ if -f "$dir/$file";
	}
	if ($found == @$f) {
	    return $dir;
	}
    }
}

sub GetTestHost {
    my($host,$comm);
    if (-f 'host') {
       ($host, $comm) = split(' ',`cat host`);
    }
    $host ||= 'localhost';
    $comm ||= 'private';
    my $resp = prompt("Enter hostname or IP address for SNMP tests: ",
		      "$host $comm");
    open(H, ">host") || die "Error: could not open file 'host' ($!)";
    print H "$resp\n";
    close H;
}

