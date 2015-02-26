#!/bin/env python

import sys
import random

seed = int(sys.argv[2])
random.seed(seed)

def gendom():
  return "".join([ chr(int(random.random()*26)+97) for x in (range(int(random.random()*30+1))) ]) + ".com"

for i in range(int(sys.argv[1])):
  print gendom()

