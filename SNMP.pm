package SNMP;
$VERSION = '1.8';   # current release version number

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
	snmp_get
        snmp_getnext
        snmp_set
        snmp_trap
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

# Package variables
tie $SNMP::debugging, SNMP::DEBUGGING;
tie $SNMP::dump_packet, SNMP::DUMP_PACKET;
tie %SNMP::MIB, SNMP::MIB;
tie $SNMP::save_descriptions, SNMP::MIB::SAVE_DESCR;

$auto_init_mib = 1; # enable automatic MIB loading at session creation time
$use_long_names = 0; # non-zero to prefer longer mib textual identifiers rather
                   # than just leaf indentifiers (see translateObj)
                   # may also be set on a per session basis(see UseLongNames)
$use_sprint_value = 0; # non-zero to enable formatting of response values
                   # using the snmp libraries "sprint_value"
                   # may also be set on a per session basis(see UseSprintValue)
                   # note: returned values not suitable for 'set' operations
$use_enums = 0; # non-zero to return integers as enums and allow sets
                # using enums where appropriate - integer data will
                # still be accepted for set operations
                # may also be set on a per session basis (see UseEnums)
%MIB = ();      # tied hash to access libraries internal mib tree structure
                # parsed in from mib files
$verbose = 0;   # controls warning/info output of SNMP module, 
                # 0 => no output, 1 => enables warning and info
                # output from SNMP module itself (is also controlled
                # by SNMP::debugging)
$debugging = 0; # non-zero to globally enable libsnmp do_debugging output
                # set to >= 2 to enabling packet dumping (see below)
$dump_packet = 0; # non-zero to globally enable libsnmp dump_packet output.
                  # is also enabled when $debugging >= 2
$save_descriptions = 0; #tied scalar to control saving descriptions during
               # mib parsing - must be set prior to mib loading

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
# if Mib is not loaded and $SNMP::auto_init_mib is enabled Mib will be loaded
# returns 'undef' upon failure
   my $obj = shift;
   my $long_names = shift || $SNMP::use_long_names;
   my $res;
   if ($obj =~ /^\.?(\d+\.)*\d+$/) {
      $res = SNMP::_translate_obj($obj,1,$long_names,$SNMP::auto_init_mib);
   } elsif ($obj =~ /(\w+)(\.\d+)*$/) {
      $res = SNMP::_translate_obj($1,0,$long_names,$SNMP::auto_init_mib);
      $res .= $2 if defined $res and defined $2;
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
# return the corresponding integer value *or* tag for a given MIB attribute
# and value. The function will sense which direction to perform the conversion
# various arg formats are supported
#    $val = SNMP::mapEnum($varbind); # note: will update $varbind
#    $val = SNMP::mapEnum('ipForwarding', 'forwarding');
#    $val = SNMP::mapEnum('ipForwarding', 1);
#
  my $var = shift;
  my ($tag, $val, $update);
  if (ref($var) =~ /ARRAY/ or ref($var) =~ /Varbind/) {
      $tag = $var->[$SNMP::Varbind::tag_f];
      $val = $var->[$SNMP::Varbind::val_f];
      $update = 1;
  } else {
      $tag = $var;
      $val = shift;
  }
  my $res = SNMP::_map_enum($tag, $val, $val =~ /^\d+$/);
  if ($update and defined $res) { $var->[$SNMP::Varbind::val_f] = $res; }
  return($res);
}

%session_params = (DestHost => 1,
		   Community => 1,
		   Version => 1,
		   Timeout => 1,
		   Retries => 1,
		   RemotePort => 1);

sub strip_session_params {
    my @params;
    my @args;
    my $param;
    while ($param = shift) {
	push(@params,$param, shift), next
	    if $session_params{$param};
	push(@args,$param);
    }
    @_ = @args;
    @params;
}


sub snmp_get {
# procedural form of 'get' method. sometimes quicker to code 
# but is less efficient since the Session is created and destroyed
# with each call. Takes all the parameters of both SNMP::Session::new and
# SNMP::Session::get (*NOTE*: this api does not support async callbacks)

    my @sess_params = &strip_session_params;
    my $sess = new SNMP::Session(@sess_params);

    $sess->get(@_);
}

sub snmp_getnext {
# procedural form of 'getnext' method. sometimes quicker to code 
# but is less efficient since the Session is created and destroyed
# with each call. Takes all the parameters of both SNMP::Session::new and
# SNMP::Session::getnext (*NOTE*: this api does not support async callbacks)

    my @sess_params = &strip_session_params;
    my $sess = new SNMP::Session(@sess_params);

    $sess->getnext(@_);
}

sub snmp_set {
# procedural form of 'set' method. sometimes quicker to code 
# but is less efficient since the Session is created and destroyed
# with each call. Takes all the parameters of both SNMP::Session::new and
# SNMP::Session::set (*NOTE*: this api does not support async callbacks)

    my @sess_params = &strip_session_params;
    my $sess = new SNMP::Session(@sess_params);

    $sess->set(@_);
}

sub snmp_trap {
# procedural form of 'trap' method. sometimes quicker to code 
# but is less efficient since the Session is created and destroyed
# with each call. Takes all the parameters of both SNMP::TrapSession::new and
# SNMP::TrapSession::trap

    my @sess_params = &strip_session_params;
    my $sess = new SNMP::TrapSession(@sess_params);

    $sess->trap(@_);
}

sub MainLoop {
    my $time = shift;
    my $callback = shift;
    my $time_sec = ($time ? int $time : 0);
    my $time_usec = ($time ? int(($time-$time_sec)*1000000) : 0);
    SNMP::_main_loop($time_sec,$time_usec,$callback);
}

package SNMP::Session;

sub new {
   my $type = shift;
   my $this = {};
   my ($name, $aliases, $host_type, $len, $thisaddr);

   %$this = @_;

   $this->{ErrorStr} = ''; # if methods return undef check for expln.
   $this->{ErrorNum} = 0;  # contains SNMP error return

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
   # flag to enable fixing pdu and retrying with a NoSuch error
   $this->{RetryNoSuch} ||= 0;

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
# *Not Implemented*
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
     my ($tag, $iid) = ($vars =~ /^((?:\.\d+)+|\w+)\.?(.*)$/);
     my $val = shift;
     $varbind_list_ref = [[$tag, $iid, $val]];
   }
   my $cb = shift;

   $res = SNMP::_set($this, $varbind_list_ref, $cb);
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
     my ($tag, $iid) = ($vars =~ /^((?:\.\d+)+|\w+)\.?(.*)$/);
     $varbind_list_ref = [[$tag, $iid]];
   }

   my $cb = shift;

   @res = SNMP::_get($this, $this->{RetryNoSuch}, $varbind_list_ref, $cb);

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
     my ($tag, $iid) = ($vars =~ /^((?:\.\d+)+|\w+)\.?(.*)$/);
     $varbind_list_ref = [[$tag, $iid]];
   }

   my $cb = shift;

   SNMP::_get($this, $this->{RetryNoSuch}, $varbind_list_ref, $cb);

   foreach $varbind (@$varbind_list_ref) {
     $sub = $this->{VarFormats}{$varbind->[$SNMP::Varbind::tag_f]} ||
	 $this->{TypeFormats}{$varbind->[$SNMP::Varbind::type_f]};
     &$sub($varbind) if defined $sub;
     push(@res, $varbind->[$SNMP::Varbind::val_f]);
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
     my ($tag, $iid) = ($vars =~ /^((?:\.\d+)+|\w+)\.?(.*)$/);
     $varbind_list_ref = [[$tag, $iid]];
   }

   my $cb = shift;

   @res = SNMP::_getnext($this, $varbind_list_ref, $cb);

   return(wantarray() ? @res : $res[0]);
}

sub fgetnext {
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
     my ($tag, $iid) = ($vars =~ /^((?:\.\d+)+|\w+)\.?(.*)$/);
     $varbind_list_ref = [[$tag, $iid]];
   }

   my $cb = shift;

   SNMP::_getnext($this, $varbind_list_ref, $cb);

   foreach $varbind (@$varbind_list_ref) {
     $sub = $this->{VarFormats}{$varbind->[$SNMP::Varbind::tag_f]} ||
	 $this->{TypeFormats}{$varbind->[$SNMP::Varbind::type_f]};
     &$sub($varbind) if defined $sub;
     push(@res, $varbind->[$SNMP::Varbind::val_f]);
   }

   return(wantarray() ? @res : $res[0]);
}

package SNMP::TrapSession;

sub new {
   my $type = shift;
   my $this = {};
   my ($name, $aliases, $host_type, $len, $thisaddr);

   %$this = @_;

   $this->{ErrorStr} = ''; # if methods return undef check for expln.
   $this->{ErrorNum} = 0;  # contains SNMP error return

   # v1 or v2, defaults to v1
   $this->{Version} ||= 1;

   # allow override of remote SNMP trap port
   $this->{RemotePort} ||= 162;

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

%trap_type = (coldStart => 0, warmStart => 1, linkDown => 2, linkUp => 3,
	      authFailure => 4, egpNeighborLoss => 5, specific => 6 );
sub trap {
# (v1) enterprise, agent, generic, specific, uptime, <vars>
# $sess->trap(enterprise=>'.1.3.6.1.4.1.2021', # or 'ucdavis' [default]
#             agent => '127.0.0.1', # or 'localhost',[default 1st intf on host]
#             generic => specific,  # can be omitted if 'specific' supplied
#             specific => 5,        # can be omitted if 'generic' supplied
#             uptime => 1234,       # default to localhost uptime (0 on win32)
#             [[ifIndex, 1, 1],[sysLocation, 0, "here"]]); # optional vars
#                                                          # always last
# (v2) srcParty, dstParty, oid, uptime, <vars>
# $sess->trap(srcParty => party1, 
#             dstParty => party2,
#             oid => 'snmpRisingAlarm',
#             uptime => 1234, 
#             [[ifIndex, 1, 1],[sysLocation, 0, "here"]]); # optional vars
#                                                          # always last
   my $this = shift;
   my $vars = pop if ref($_[$#_]); # last arg may be varbind or varlist
   my %param = @_;
   my ($varbind_list_ref, @res);

   if (ref($vars) =~ /SNMP::VarList/) {
     $varbind_list_ref = $vars;
   } elsif (ref($vars) =~ /SNMP::Varbind/) {
     $varbind_list_ref = [$vars];
   } elsif (ref($vars) =~ /ARRAY/) {
     $varbind_list_ref = [$vars];
     $varbind_list_ref = $vars if ref($$vars[0]) =~ /ARRAY/;
   }

   if ($this->{Version} == 1) {
       my $enterprise = $param{enterprise} || 'ucdavis';
       $enterprise = SNMP::translateObj($enterprise) 
	   unless $enterprise =~ /^[\.\d]+$/;
       my $agent = $param{agent} || '';
       my $generic = $param{generic} || 'specific';
       $generic = $trap_type{$generic} || $generic;
       my $uptime = $param{uptime} || SNMP::_sys_uptime();
       my $specific = $param{specific} || 0;
       @res = SNMP::_trapV1($this, $enterprise, $agent, $generic, $specific, 
			  $uptime, $varbind_list_ref);
   } else {
       my $dstParty = $param{dstParty};
       my $srcParty = $param{srcParty};
       my $oid = $param{oid};
       my $uptime = $param{uptime};
       @res = SNMP::_trapV2($this, $dstParty, $srcParty, $oid, 
			  $uptime, $varbind_list_ref);
   }

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

#sub DESTROY {
#    print "SNMP::Varbind::DESTROY($_[0])\n";
#}

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

#sub DESTROY {
#    print "SNMP::VarList::DESTROY($_[0])\n";
#}

package SNMP::DEBUGGING;
# controls info/debugging output from SNMP module and libsnmp
# $SNMP::debugging == 1    =>   enables general info and warning output
#                                (eqiv. to setting $SNMP::verbose)
# $SNMP::debugging == 2    =>   enables do_debugging from libsnmp as well
# $SNMP::debugging == 3    =>   enables packet_dump from libsnmp as well
sub TIESCALAR { my $class = shift; my $val; bless \$val, $class; }

sub FETCH { ${$_[0]}; }

sub STORE { 
    $SNMP::verbose = $_[1];
    SNMP::_set_debugging($_[1]>1); 
    $SNMP::dump_packet = ($_[1]>2); 
    ${$_[0]} = $_[1]; 
}

sub DELETE { 
    $SNMP::verbose = 0; 
    SNMP::_set_debugging(0); 
    $SNMP::dump_packet = 0; 
    ${$_[0]} = undef; 
}

package SNMP::DUMP_PACKET;
# controls packet dump output from libsnmp

sub TIESCALAR { my $class = shift; my $val; bless \$val, $class; }

sub FETCH { ${$_[0]}; }

sub STORE { SNMP::_dump_packet($_[1]); ${$_[0]} = $_[1]; }

sub DELETE { SNMP::_dump_packet(0); ${$_[0]} = 0; }

package SNMP::MIB;

sub TIEHASH {
    bless {};
}

sub FETCH {
    my $this = shift;
    my $key = shift;

    if (!defined $this->{$key}) {
	tie(%{$this->{$key}}, SNMP::MIB::NODE, $key) or return undef;
    }
    $this->{$key};
}

sub STORE {
    warn "STORE(@_) : write access to the MIB not implemented\n";
}

sub DELETE {
    delete $_[0]->{$_[1]}; # just delete cache entry
}

sub FIRSTKEY { return '.1'; } # this should actually start at .0 but
                              # because nodes are not stored in lexico
                              # order in ucd-snmp node tree walk will
                              # miss most of the tree
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
     label => 0,    # leaf textual identifier (e.g., 'sysDescr')
     subID => 0,    # leaf numeric OID component of objectID (e.g., '1')
     moduleID => 0, # textual identifier for module (e.g., 'RFC1213-MIB')
     parent => 0,   # parent node
     children => 0, # array reference of children nodes
     nextNode => 0, # next lexico node (BUG! does not return in lexico order)
     type => 0,     # returns simple type (see getType for values)
     access => 0,   # returns ACCESS (ReadOnly, ReadWrite, WriteOnly, 
                    # NoAccess, Notify, Create)
     status => 0,   # returns STATUS (Mandatory, Optional, Obsolete, 
                    # Deprecated)
     syntax => 0,   # returns 'textualConvention' if defined else 'type'
     textualConvention => 0, # returns TEXTUAL-CONVENTION
     units => 0,    # returns UNITS
     hint => 0,     # returns HINT
     enums => 0,    # returns hash ref {tag => num, ...}
     description => 0, # returns DESCRIPTION ($SNMP::save_descriptions must
                    # be set prior to MIB initialization/parsing
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

#sub DESTROY {
#    warn "DESTROY(@_): write access to MIB node not implemented\n";
#    # print "SNMP::MIB::NODE::DESTROY : $_[0]->{label} ($_[0])\n";
#}
package SNMP::MIB::SAVE_DESCR;

sub TIESCALAR { my $class = shift; my $val; bless \$val, $class; }

sub FETCH { ${$_[0]}; }

sub STORE { SNMP::_set_save_descriptions($_[1]); ${$_[0]} = $_[1]; }

sub DELETE { SNMP::_set_save_descriptions(0); ${$_[0]} = 0; }

package SNMP;
END{SNMP::_sock_cleanup() if defined &SNMP::_sock_cleanup;}
# Autoload methods go after __END__, and are processed by the autosplit prog.

1;
__END__
