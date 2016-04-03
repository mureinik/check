# Copyright 2016 Nir Soffer <nsoffer@redhat.com>
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v2 or (at your option) any later version.

import random
import subprocess
import sys
import time

if len(sys.argv) > 1:
    paths_count = int(sys.argv[1], 10)
else:
    paths_count = 100

with open("loop.log", "a") as log:
    p = subprocess.Popen(["./loop"],
                         stdin=subprocess.PIPE,
                         stdout=subprocess.PIPE,
                         stderr=log)
    paths = ["%06d" % i for i in range(paths_count)]
    for path in paths:
        p.stdin.write("start %s\n" % path)
        time.sleep(random.random() * 0.1)
    try:
        p.wait()
    except KeyboardInterrupt:
        pass
    for path in paths:
        p.stdin.write("stop %s\n" % path)
