#!/bin/bash

DNSBIN=`realpath ../dns`

SEED=$RANDOM
echo "Random seed: $SEED"

rm -rf regress_db/

# 1st case, create 1M records
./domaingen.py 1000000 $SEED | gzip > 1M.txt.gz
zcat 1M.txt.gz | sort | gzip > 1M_s.txt.gz
$DNSBIN regress_db/ add-domains 1M.txt.gz
$DNSBIN regress_db/ add-domains 1M_s.txt.gz

# 2nd case, read it

# 3rd case, create 1M random

# 4th case, read it

