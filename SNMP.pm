package SNMP;
$VERSION = 1.7;   # current release version number

require Exporter;
require DynaLoader;
require AutoLoader;

@SNMP::ISA = qw(Exporter AutoLoader DynaLoader);
# Items to export into callers namespace by default. Note: do not export
# names by default without a very good reason. Use EXPORT_OK instead.
# Do not simply export all your public functions/methods/constants.
@SNMP::EXPORT = qw(
	RECEIVED_MESSAGE
	SNMPERR_BAD_ADDRESS
	SNMPERR_BAD_LOCPORT
	SNMPERR_BAD_SESSION
	SNMPERR_GENERR
	SNMPERR_TOO_LONG
	SNMP_DEFAULT_ADDRESS
	SNMP_DEFAULT_COMMUNITY_LEN
	SNMP_DEFAULT_ENTERPRISE_LENGTH
	SNMP_DEFAULT_ERRINDEX
	SNMP_DEFAULT_ERRSTAT
	SNMP_DEFAULT_PEERNAME
	SNMP_DEFAULT_REMPORT
	SNMP_DEFAULT_REQID
	SNMP_DEFAULT_RETRIES
	SNMP_DEFAULT_TIME
	SNMP_DEFAULT_TIMEOUT
	SNMP_DEFAULT_VERSION
	TIMED_OUT
);
sub AUTOLOAD {
    # This AUTOLOAD is used to 'autoload' constants from the constant()
    # XS function.  If a constant is not found then control is passed
    # to the AUTOLOAD in AutoLoader.
    my($val,$pack,$file,$line);
    local($constname);
    ($constname = $AUTOLOAD) =~ s/.*:://;
    $val = constant($constname, @_ ? $_[0] : 0);
    if ($! != 0) {
	if ($! =~ /Invalid/) {
	    $AutoLoader::AUTOLOAD = $AUTOLOAD;
	    goto &AutoLoader::AUTOLOAD;
	}
	else {
	    ($pack,$file,$line) = caller;
	    die "Your vendor has not defined SNMP macro $constname, used at $file line $line.
";
	}
    }
    eval "sub $AUTOLOAD { $val }";
    goto &$AUTOLOAD;
}

bootstrap SNMP;

# Preloaded methods go here.
$auto_init_mib = 1; # DEPRECATED
$mib_loaded = 0; # flag to indicate if mib has been loaded. mib loading
                 # routines set this flag as a side effect. flag is checked
                 # upon session creation and if false triggers auto loading
$verbose = 0; # set to false, limit extraneous I/O
$use_long_names = 0; # set to 1 to prefer longer mib textual identifiers rather
                     # than just leaf indentifiers in translateObj

sub setMib {
# loads mib from file name provided
# setting second arg to true causes currently loaded mib to be replaced
# otherwise mib file will be added to existing loaded mib database
# NOTE: now deprecated in favor of setMibFiles and new module based funcs
   my $file = shift;
   my $force = shift || '0';
   return 0 if $file and not (-r $file);
   SNMP::_read_mib($file,$force);
   $SNMP::mib_loaded = 1;
}

sub setMibFiles {
# replaces currently loaded mib database with mib defined in
# file(s) supplied - if no files supplied, will call init_mib and
# rely entirely on ucd environment variable settings (see man mib_api)
   my $file = shift || '';

   SNMP::_read_mib($file, 1) unless $file and not (-r $file);
   foreach $file (@_) {
     next if $file and not (-r $file);
     SNMP::_read_mib($file);
   }
   $SNMP::mib_loaded = 1;
}

sub addMibFiles {
# adds mib definitions to currently loaded mib database from
# file(s) supplied - if no files supplied, will call init_mib and
# rely entirely on ucd environment variable settings (see man mib_api)
   my $file = shift || '';
   SNMP::_read_mib($file) unless $file and not (-r $file);
   foreach $file (@_) {
     next if $file and not (-r $file);
     SNMP::_read_mib($file);
   }
   $SNMP::mib_loaded = 1;
}

sub setMibDirs {
# ideally this would reinitialize currently defined mib search directories
# but no api for that that I can find so this function just adds to mib
# search dirs identical to addMibDirs
  my $dir;
  foreach $dir (@_) {
    SNMP::_add_mib_dir($dir);
  }
  SNMP::_init_mib_internals();
}

sub addMibDirs {
  my $dir;
  foreach $dir (@_) {
    SNMP::_add_mib_dir($dir);
  }
  SNMP::_init_mib_internals();
}

sub setModules {
# replaces currently loaded mib database with mib definitions from supplied
# modules. Modules will be searched from previously defined mib search dirs
   my $mod = shift || '';
   SNMP::_read_module($mod);
   foreach $mod (@_) {
     SNMP::_read_module($mod);
   }
   $SNMP::mib_loaded = 1;
}

sub addModules {
# adds mib definitions from supplied modules to currently loaded mib database.
# Modules will be searched from previously defined mib search dirs
   my $mod = shift;
   $mod =~ s/^ALL$//;
   SNMP::_read_module($mod);
   foreach $mod (@_) {
     SNMP::_read_module($mod);
   }
   $SNMP::mib_loaded = 1;
}

sub translateObj {
# translate object identifier(tag or numeric) into alternate representation
# (i.e., sysDescr => '.1.3.6.1.2.1.1.1' and '.1.3.6.1.2.1.1.1' => sysDescr)
# when $SNMP::use_long_names or second arg is non-zero the translation will
# return longer textual identifiers (e.g., system.sysDescr)
   my $obj = shift;
   my $use_long_names = shift || $SNMP::use_long_names;

   if ($obj =~ /^\.?(\d+\.)*\d+$/) {
      SNMP::_translate_obj($obj,1,$use_long_names);
   } elsif ($obj =~ /(\w+)+(\.\d+)*$/) {
      SNMP::_translate_obj($1,0,$use_long_names) . $2;
   } else {
      undef;
   }
}

sub getType {
# return SNMP data type for given textual identifier
# OBJECTID, OCTETSTR, INTEGER, NETADDR, IPADDR, COUNTER
# GAUGE, TIMETICKS, OPAQUE, or undef
  my $tag = shift;
  SNMP::_get_type($tag);
}

sub mapEnum {
  my $varbind = shift;

  SNMP::_map_enum($varbind->[$SNMP::Varbind::tag_f]);
}

package SNMP::Session;

sub new {
   my $type = shift;
   my $this = {};
   my ($name, $aliases, $host_type, $len, $thisaddr);

   %$this = @_;

   $this->{ErrorStr} = ''; # if methods return undef check for expln.
   $this->{ErrorNum} = 0;  # contains SNMP error return

   $this->{RetryNoSuch} ||= 1; # on NOSUCHNAME/GETREQ fix pdu and get again

   # v1 or v2, defaults to v1
   $this->{Version} ||= 1;

   # allow override of remote SNMP port
   $this->{RemotePort} ||= 161;

   # destination host defaults to localhost
   $this->{DestHost} ||= 'localhost';

   # community defaults to public
   $this->{Community} ||= 'public';

   # number of retries before giving up, defaults to SNMP_DEFAULT_RETRIES
   $this->{Retries} = SNMP::SNMP_DEFAULT_RETRIES() unless defined($this->{Retries});

   # timeout before retry, defaults to SNMP_DEFAULT_TIMEOUT
   $this->{Timeout} = SNMP::SNMP_DEFAULT_TIMEOUT() unless defined($this->{Timeout});

   # convert to dotted ip addr if needed
   if ($this->{DestHost} =~ /\d+\.\d+\.\d+\.\d+/) {
     $this->{DestAddr} = $this->{DestHost};
   } else {
     ($name, $aliases, $host_type, $len, $thisaddr) =
       gethostbyname($this->{DestHost});
     $this->{DestAddr} = join('.', unpack("C4", $thisaddr));
   }
   warn("undefined destination address!") unless $this->{DestAddr};

   $this->{SessPtr} = SNMP::_new_session($this->{Version},
					 $this->{Community},
					 $this->{DestAddr},
					 $this->{RemotePort},
					 $this->{Retries},
					 $this->{Timeout},
					);
   # if mib is not already loaded try to load with no parameters
   # will attempt to load according to environment variables
   SNMP::setMibFiles() unless $SNMP::mib_loaded;

   bless $this;
}

sub set {
   my $this = shift;
   my $vars = shift;
   my $varbind_list_ref;
   my $res = 0;

   if (ref($vars) =~ /SNMP::VarList/) {
     $varbind_list_ref = $vars;
   } elsif (ref($vars) =~ /SNMP::Varbind/) {
     $varbind_list_ref = [$vars];
   } elsif (ref($vars) =~ /ARRAY/) {
     $varbind_list_ref = [$vars];
     $varbind_list_ref = $vars if ref($$vars[0]) =~ /ARRAY/;
   } else {
     my ($tag, $iid) = ($vars =~ /^(\w+)\.(.*)$/);
     my $val = shift;
     $varbind_list_ref = [[$tag, $iid, $val]];
   }

   $res = SNMP::_set($this, $varbind_list_ref);

}

sub get {
   my $this = shift;
   my $vars = shift;
   my ($varbind_list_ref, @res);


   if (ref($vars) =~ /SNMP::VarList/) {
     $varbind_list_ref = $vars;
   } elsif (ref($vars) =~ /SNMP::Varbind/) {
     $varbind_list_ref = [$vars];
   } elsif (ref($vars) =~ /ARRAY/) {
     $varbind_list_ref = [$vars];
     $varbind_list_ref = $vars if ref($$vars[0]) =~ /ARRAY/;
   } else {
     my ($tag, $iid) = ($vars =~ /^(\w+)\.(.*)$/);
     $varbind_list_ref = [[$tag, $iid]];
   }

   @res = SNMP::_get($this, $this->{RetryNoSuch}, $varbind_list_ref);

   return(wantarray() ? @res : $res[0]);
}

sub fget {
   my $this = shift;
   my $vars = shift;
   my ($varbind_list_ref, @res);


   if (ref($vars) =~ /SNMP::VarList/) {
     $varbind_list_ref = $vars;
   } elsif (ref($vars) =~ /SNMP::Varbind/) {
     $varbind_list_ref = [$vars];
   } elsif (ref($vars) =~ /ARRAY/) {
     $varbind_list_ref = [$vars];
     $varbind_list_ref = $vars if ref($$vars[0]) =~ /ARRAY/;
   } else {
     my ($tag, $iid) = ($vars =~ /^(\w+)\.(.*)$/);
     $varbind_list_ref = [[$tag, $iid]];
   }

   @res = SNMP::_get($this, $this->{RetryNoSuch}, $varbind_list_ref);

   foreach $varbind (@$varbind_list_ref) {
     if ($sub = $this->{VarFormats}{$varbind->[$SNMP::Varbind::tag_f]}) {
       $varbind->[$SNMP::Varbind::val_f] = &$sub($varbind);
     } elsif ($sub = $this->{TypeFormats}{$varbind->[$SNMP::Varbind::type_f]}){
       $varbind->[$SNMP::Varbind::val_f] = &$sub($varbind);
     }
   }

   return(wantarray() ? @res : $res[0]);
}

sub getnext {
   my $this = shift;
   my $vars = shift;
   my ($varbind_list_ref, @res);

   if (ref($vars) =~ /SNMP::VarList/) {
     $varbind_list_ref = $vars;
   } elsif (ref($vars) =~ /SNMP::Varbind/) {
     $varbind_list_ref = [$vars];
   } elsif (ref($vars) =~ /ARRAY/) {
     $varbind_list_ref = [$vars];
     $varbind_list_ref = $vars if ref($$vars[0]) =~ /ARRAY/;
   } else {
     my ($tag, $iid) = ($vars =~ /^(\w+)\.(.*)$/);
     $varbind_list_ref = [[$tag, $iid]];
   }

   @res = SNMP::_getnext($this, $varbind_list_ref);

   return(wantarray() ? @res : $res[0]);
}


package SNMP::Varbind;

$tag_f = 0;
$iid_f = 1;
$val_f = 2;
$type_f = 3;

sub new {
   my $type = shift;
   my $this = shift;

   bless $this;
}

sub tag {
  $_[0]->[$tag_f];
}

sub iid {
  $_[0]->[$iid_f];
}

sub val {
  $_[0]->[$val_f];
}

sub type {
  $_[0]->[$type_f];
}

package SNMP::VarList;

sub new {
   my $type = shift;
   my $this = [];
   my $varb;
   foreach $varb (@_) {
     $varb = new SNMP::Varbind($varb) unless ref($varb) =~ /SNMP::Varbind/;
     push(@{$this}, $varb);
   }

   bless $this;
}

package SNMP;

# Autoload methods go after __END__, and are processed by the autosplit prog.

1;
__END__
