#! /bin/bash

# solve.sh  # To find candidates.


# Best seems to be EV and the consensus prefix appears to be EVINKCTO
./heavy -cf stage6.txt -bf bigrams_x.eng -pre EVINKCTO -nl 65536 -nh 65536

# Encrypt using the best key.
./playfair -cf stage6.txt -d -k EVINKCTORHALUGBMFSPDWXYZQ