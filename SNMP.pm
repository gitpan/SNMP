package SNMP;
$VERSION = 1.6;   # current release version number

require Exporter;
require DynaLoader;
require AutoLoader;

@SNMP::ISA = qw(Exporter Autoloader DynaLoader);
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
$auto_init_mib = 1; # set to true, mib is loaded on session creation
                    # set to zero(0) for manual control

sub setMib {
# re-initializes mib with file name provided
   my ($file,$force) = @_;
   SNMP::_setmib($file,$force);
}

sub translateObj {
# translate object identifier(tag or numeric) into alternate representation
# (i.e., sysDescr => '.1.3.6.1.2.1.1.1' and '.1.3.6.1.2.1.1.1' => sysDescr)
   my $obj = shift;

   if ($obj =~ /^\.?(\d+\.)*\d+$/) {
      SNMP::_translate($obj,1);
   } elsif ($obj =~ /(\w+)+(\.\d+)*$/) {
      SNMP::_translate($1,0) . $2;
   } else {
      undef;
   }
}

package SNMP::Session;

sub new {
   my $type = shift;
   my $this = {};
   my ($name, $aliases, $type, $len, $thisaddr);

   %$this = @_;

   $this->{ErrorStr} = ''; # if methods return undef check for expln.
   $this->{ErrorNum} = 0;  # contains SNMP error return

   $this->{RetryNoSuch} ||= 1; # on NOSUCHNAME/GETREQ fix pdu and get again

   # v1 or v2, defaults to v1
   $this->{Version} ||= 1;

   # community defaults to public 
   $this->{Community} ||= 'public'; 

   # number of retries before giving up, defaults to SNMP_DEFAULT_RETRIES
   $this->{Retries} = SNMP::SNMP_DEFAULT_RETRIES() unless defined($this->{Retries});

   # timeout before retry, defaults to SNMP_DEFAULT_TIMEOUT
   $this->{Timeout} = SNMP::SNMP_DEFAULT_TIMEOUT() unless defined($this->{Timeout});

   # convert to dotted ip addr if needed 
#   if ($this->{DestHost} =~ /[0-255]\.[0-255]\.[0-255]\.[0-255]/) {
   if ($this->{DestHost} =~ /\d+\.\d+\.\d+\.\d+/) {
      $this->{DestAddr} = $this->{DestHost};
   } elsif (defined($this->{DestHost})) {
     ($name, $aliases, $type, $len, $thisaddr) = 
        gethostbyname($this->{DestHost});
      $this->{DestAddr} = join('.', unpack("C4", $thisaddr));
   } else {
     warn("undefined destination host!");
   }

   $this->{SessPtr} = SNMP::_new_session($this->{Version},
					 $this->{Community},
					 $this->{DestAddr},
					 $this->{Retries},
					 $this->{Timeout},
					);

   SNMP::setMib() if $SNMP::auto_init_mib;

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

sub new {
   my $type = shift;
   my $this = shift;

   bless $this;
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
