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
$verbose = 0; # set to false, limit extraneous I/O
$use_long_names = 0; # set to 1 to prefer longer mib textual identifiers rather
                     # than just leaf indentifiers in translateObj

sub setMib {
# loads mib from file name provided
# setting second arg to true causes currently loaded mib to be replaced
# otherwise mib file will be added to existing loaded mib database
# NOTE: now deprecated in favor of addMibFiles and new module based funcs
   my $file = shift;
   my $force = shift || '0';
   return 0 if $file and not (-r $file);
   SNMP::_read_mib($file,$force);
}

sub initMib {
# eqivalent to calling init_mib if the mib database is empty (ie Mib is NULL)
# if Mib is already loaded this function does nothing
  SNMP::_read_mib("");
}

sub addMibDirs {
# adds directories to search path when a module is requested to be loaded
  foreach (@_) {
    SNMP::_add_mib_dir($_);
  }
}

sub addMibFiles {
# adds mib definitions to currently loaded mib database from
# file(s) supplied
  foreach (@_) {
    SNMP::_read_mib($_);
  }
}

sub addModules {
# adds mib module definitions to currently loaded mib database.
# Modules will be searched from previously defined mib search dirs
# Passing and arg of 'ALL' will cause all known modules to be loaded
   foreach (@_) {
     SNMP::_read_module($_);
   }
}

sub removeModules {
# causes modules to be unloaded from mib database
# Passing and arg of 'ALL' will cause all known modules to be unloaded
  warn("SNMP::unloadModules not implemented! (yet)");
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

   SNMP::initMib(); # this call ensures that *some* mib is loaded

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
