package SNMP;
$VERSION = '1.8a1';   # current release version number

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
    # croak "&$module::constant not defined" if $constname eq 'constant';
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
$auto_init_mib = 1; # enable automatic MIB loading at session creation time
$verbose = 0; # non-zero for debugging and status output
$use_long_names = 0; # non-zero to prefer longer mib textual identifiers rather
                     # than just leaf indentifiers (see translateObj)
                     # may also be set on a per session basis
$use_sprint_value = 0; # non-zero to enable formatting of response values
                   # using the snmp libraries "sprint_value"
                   # may also be set on a per session basis
                   # note: returned values not suitable for 'set' operations
$use_enums = 0; # non-zero to return integers as enums and allow sets
                # using enums where appropriate - integer data will
                # still be accepted for set operations
                # may also be set on a per session basis
%MIB = ();     # tied hash to library internal mib tree structure from
                # parsed mib
$save_descriptions = 0; #tied scalar to control saving descriptions during
               # mib parsing - must be set prior to mib loading

tie %SNMP::MIB, SNMP::MIB;
tie $SNMP::save_descriptions, SNMP::MIB::SAVE_DESCR;

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
# eqivalent to calling the snmp library init_mib if Mib is NULL
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

sub loadModules {
# adds mib module definitions to currently loaded mib database.
# Modules will be searched from previously defined mib search dirs
# Passing and arg of 'ALL' will cause all known modules to be loaded
   foreach (@_) {
     SNMP::_read_module($_);
   }
}

sub unloadModules {
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
   my $long_names = shift || $SNMP::use_long_names;
   my $res;
   if ($obj =~ /^\.?(\d+\.)*\d+$/) {
      $res = SNMP::_translate_obj($obj,1,$long_names);
   } elsif ($obj =~ /(\w+)+(\.\d+)*$/) {
      $res = SNMP::_translate_obj($1,0,$long_names);
      $res .= $2 if defined $2;
   }

   return($res);
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

  # SNMP::_map_enum($varbind->[$SNMP::Varbind::tag_f]);
}

sub snmp_get {

}

sub snmp_getnext {

}

sub snmp_set {

}

sub snmp_trap {

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
     if (($name, $aliases, $host_type, $len, $thisaddr) =
	 gethostbyname($this->{DestHost})) {
	 $this->{DestAddr} = join('.', unpack("C4", $thisaddr));
     } else {
	 warn("unable to resolve destination address($this->{DestHost}!")
	     if $SNMP::verbose;
	 return undef;
     }
   }

   $this->{SessPtr} = SNMP::_new_session($this->{Version},
					 $this->{Community},
					 $this->{DestAddr},
					 $this->{RemotePort},
					 $this->{Retries},
					 $this->{Timeout},
					);

   return undef unless $this->{SessPtr};

   SNMP::initMib() if $SNMP::auto_init_mib; # ensures that *some* mib is loaded

   $this->{UseLongNames} ||= $SNMP::use_long_names;
   $this->{UseSprintValue} ||= $SNMP::use_sprint_value;
   $this->{UseEnums} ||= $SNMP::use_enums;

   bless $this;
}

sub update {
# designed to update the fields of session to allow retargettinf to different
# host, community name change, timeout, retry changes etc. Unfortunately not
# working yet because some updates (the address in particular) need to be 
# done on the internal session pointer which cannot be fetched w/o touching
# globals at this point which breaks win32. A patch to the ucd-snmp toolkit 
# is needed
   my $this = shift;
   my ($name, $aliases, $host_type, $len, $thisaddr);
   my %new_fields = @_;

   @$this{keys %new_fields} = values %new_fields;

   # convert to dotted ip addr if needed
   if (exists $new_fields{DestHost}) {
      if ($this->{DestHost} =~ /\d+\.\d+\.\d+\.\d+/) {
        $this->{DestAddr} = $this->{DestHost};
      } else {
        if (($name, $aliases, $host_type, $len, $thisaddr) =
           gethostbyname($this->{DestHost})) {
           $this->{DestAddr} = join('.', unpack("C4", $thisaddr));
        } else {
           warn("unable to resolve destination address($this->{DestHost}!")
              if $SNMP::verbose;
           return undef;
        }
      }
   }

   $this->{UseLongNames} ||= $SNMP::use_long_names;
   $this->{UseSprintValue} ||= $SNMP::use_sprint_value;
   $this->{UseEnums} ||= $SNMP::use_enums;

   SNMP::_update_session($this->{Version},
		 $this->{Community},
		 $this->{DestAddr},
		 $this->{RemotePort},
		 $this->{Retries},
		 $this->{Timeout},
		);

  
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
   # BUG --- Use of uninitialized value w/ no agent present --- BUG
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
   $this ||= [];
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

package SNMP::MIB;

sub TIEHASH {
    bless {};
}

sub FETCH {
    my $this = shift;
    my $key = shift;
    if (!defined $this->{$key}) {
        tie %{$this->{$key}}, SNMP::MIB::NODE, $key;
    }
    $this->{$key};
}

sub STORE {
    warn "STORE(@_) : write access to the MIB not implemented\n";
}

sub DELETE {
    delete $_[0]->{$_[1]}; # just delete cache entry
}

sub FIRSTKEY { return '.1'; }
sub NEXTKEY { # this could be sped up by using an XS __get_next_oid maybe
   my $node = $_[0]->FETCH($_[1])->{nextNode};
   $node->{objectID};  
} 
sub EXISTS { exists $_[0]->{$_[1]} || $_[0]->FETCH($_[1]); }
sub CLEAR { undef %{$_[0]}; } # clear the cache

package SNMP::MIB::NODE;
my %node_elements = 
    (
     objectID => 0, # dotted decimal fully qualified OID
     label => 0,
     subID => 0,
     moduleID => 0,
     parent => 0,   # parent node
     children => 0, # array ref child nodes
     nextNode => 0,     # next lexico node
     type => 0,
     access => 0,
     status => 0,
     units => 0,
     hint => 0,
     enums => 0,    # hash ref {tag => num, ...}
     description => 0,
    );

# sub TIEHASH - implemented in SNMP.xs

# sub FETCH - implemented in SNMP.xs

sub STORE {
    warn "STORE(@_): write access to MIB node not implemented\n";
}

sub DELETE {
    warn "DELETE(@_): write access to MIB node not implemented\n";
}

sub FIRSTKEY { my $k = keys %node_elements; (each(%node_elements))[0]; }
sub NEXTKEY { (each(%node_elements))[0]; }
sub EXISTS { exists($node_elements{$_[1]}); }
sub CLEAR {  
    warn "CLEAR(@_): write access to MIB node not implemented\n";
}

sub DESTROY {
    print "SNMP::MIB::NODE - I'm destroyed\n$_[0]->{label}($_[0])\n";
}
package SNMP::MIB::SAVE_DESCR;

sub TIESCALAR { my $class = shift; my $val; bless \$val, $class; }

sub FETCH { $$_[0]; }

sub STORE { SNMP::_set_save_descriptions($_[1]); $$_[0] = $_[1]; }

sub DELETE { SNMP::_set_save_descriptions(0); $$_[0] = 0; }

package SNMP;
END{SNMP::_sock_cleanup() if defined &SNMP::_sock_cleanup;}
# Autoload methods go after __END__, and are processed by the autosplit prog.

1;
__END__
