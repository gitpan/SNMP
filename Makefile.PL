use ExtUtils::MakeMaker;
require 5;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

%MakeParams = InitMakeParams();

WriteMakefile(%MakeParams);

sub InitMakeParams {
my %Params = (
    'NAME'	=> 'SNMP',
    'VERSION'	=> 1.6,
    'dist'      => { SUFFIX => "gz", COMPRESS => "gzip -9f"},
	    );
my @IncludeFiles = qw[asn1.h parse.h snmp.h snmp_api.h 
		      snmp_client.h snmp_impl.h];

my @IncludeDirs = qw[/usr/include /usr/local/include];

my $IncludeDir = find_files(\@IncludeFiles,\@IncludeDirs) ||
	prompt("Where are the cmu-snmpv2 include files installed?","/usr/local/include");

my $LibDir = find_files(["libsnmp.a"],[qw[/usr/lib /usr/local/lib]]) ||
	prompt("Where is libsnmp.a installed?","/usr/local/lib");

   @IncludeFiles = map {"$IncludeDir/$_";} @IncludeFiles;
   $Params{LIBS} = "-L$LibDir -lsnmp";
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

sub MY::test {
  qq{

 test:\n\t\$(FULLPERL) -w -I\$(INST_LIB) t/snmptest.pl

 };
}
