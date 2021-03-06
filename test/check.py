# Copyright 2016 Nir Soffer <nsoffer@redhat.com>
#
# This copyrighted material is made available to anyone wishing to use,
# modify, copy, or redistribute it subject to the terms and conditions
# of the GNU General Public License v2 or (at your option) any later version.

import glob
import random
import subprocess
import sys
import time

with open("check.log", "a") as log:
    # Use current stdout to consume process output
    p = subprocess.Popen(["./check"] + sys.argv[1:],
                         stdin=subprocess.PIPE,
                         stderr=log)
    paths = glob.glob("/rhev/data-center/mnt/*/*/dom_md/metadata")
    for path in paths:
        p.stdin.write("start %s 10\n" % path)
        p.stdin.flush()
        time.sleep(random.random() * 0.1)
    try:
        p.wait()
    except KeyboardInterrupt:
        pass
    for path in paths:
        p.stdin.write("stop %s\n" % path)
