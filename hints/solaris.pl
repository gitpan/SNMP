# so we can find bcopy
$self->{LIBS} = join(' ', $self->{LIBS}, "-L/usr/ucblib -lucb"); 
