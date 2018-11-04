#!/usr/bin/env python

import os

def c():
    return os.getpid() % 100000

def b():
    return c() + 1

def a():
    return b() - 1

def main():
    ret = 0
    pid = os.fork()
    if pid:
        os.wait()

    ret += a()

    return ret

if __name__=='__main__':
    main()
