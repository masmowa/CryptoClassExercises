#! /bin/bash

for i in A B C D F G H I K L M N O P Q R S T U V W X Y Z; do
    echo "Testing E$i"
    ./heavy -cf cipher.txt -sf Output/candidates.$i -bf bigrams_x.eng -nl 131072 -nh 131072 -pre E$i
done

