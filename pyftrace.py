#! /usr/bin/env python
### /usr/bin/env python3.5

from __future__ import print_function

__all__ = ['Trace']
import linecache
import os
import re
import sys
from warnings import warn as _warn
import time
import copy

TERM_COLOR_NORMAL  = ""
TERM_COLOR_RESET   = "\033[0m"
TERM_COLOR_BOLD    = "\033[1m"
TERM_COLOR_RED     = "\033[91m"    # bright red
TERM_COLOR_GREEN   = "\033[32m"
TERM_COLOR_YELLOW  = "\033[33m"
TERM_COLOR_BLUE    = "\033[94m"    # bright blue
TERM_COLOR_MAGENTA = "\033[35m"
TERM_COLOR_CYAN    = "\033[36m"
TERM_COLOR_GRAY    = "\033[90m"    # bright black

try:
    import threading
except ImportError:
    _settrace = sys.settrace

    def _unsettrace():
        sys.settrace(None)
else:
    def _settrace(func):
        threading.settrace(func)
        sys.settrace(func)

    def _unsettrace():
        sys.settrace(None)
        threading.settrace(None)

def _usage(outfile):
    outfile.write("""Usage: %s [OPTIONS] <file> [ARGS]

Meta-options:
--help                Display this help then exit.

Filters, may be repeated multiple times:
--ignore-module=<mod> Ignore the given module(s) and its submodules
                      (if it is a package).  Accepts comma separated
                      list of module names
--ignore-dir=<dir>    Ignore files in the given directory (multiple
                      directories can be joined by os.pathsep).
""" % sys.argv[0])

# Simple rx to find lines with no code.
rx_blank = re.compile(r'^\s*(#.*)?$')

class _Ignore:
    def __init__(self, modules=None, dirs=None):
        self._mods = set() if not modules else set(modules)
        self._dirs = [] if not dirs else [os.path.normpath(d)
                                          for d in dirs]
        self._ignore = { '<string>': 1 }

    def names(self, filename, modulename):
        if modulename in self._ignore:
            return self._ignore[modulename]

        # haven't seen this one before, so see if the module name is
        # on the ignore list.
        if modulename in self._mods:  # Identical names, so ignore
            self._ignore[modulename] = 1
            return 1

        # check if the module is a proper submodule of something on
        # the ignore list
        for mod in self._mods:
            # Need to take some care since ignoring
            # "cmp" mustn't mean ignoring "cmpcache" but ignoring
            # "Spam" must also mean ignoring "Spam.Eggs".
            if modulename.startswith(mod + '.'):
                self._ignore[modulename] = 1
                return 1

        # Now check that filename isn't in one of the directories
        if filename is None:
            # must be a built-in, so we must ignore
            self._ignore[modulename] = 1
            return 1

        # Ignore a file when it contains one of the ignorable paths
        for d in self._dirs:
            # The '+ os.sep' is to ensure that d is a parent directory,
            # as compared to cases like:
            #  d = "/usr/local"
            #  filename = "/usr/local.py"
            # or
            #  d = "/usr/local.py"
            #  filename = "/usr/local.py"
            if filename.startswith(d + os.sep):
                self._ignore[modulename] = 1
                return 1

        # Tried the different ways, so we don't ignore this module
        self._ignore[modulename] = 0
        return 0

def _modname(path):
    """Return a plausible module name for the patch."""

    base = os.path.basename(path)
    filename, ext = os.path.splitext(base)
    return filename

def get_time_and_unit(duration):
    duration = float(duration)
    time_unit = ""

    if duration < 100:
        divider = 1
        time_unit = "ns"
    elif duration < 1000000:
        divider = 1000
        time_unit = "us"
    elif duration < 1000000000:
        divider = 1000000
        time_unit = "ms"
    else:
        divider = 1000000000
        time_unit = " s"

    return (duration / divider, time_unit)

class Trace:
    def __init__(self,
                 ignoremods=(), ignoredirs=(),
                 opt_line=False, opt_retval=False):
        """
        @param ignoremods a list of the names of modules to ignore
        @param ignoredirs a list of the names of directories to ignore
                     all of the (recursive) contents of
        """
        pid = os.getpid()
        self.ignore = _Ignore(ignoremods, ignoredirs)
        self.donothing = 0
        self.start_time = None
        self.mtd = {}
        self.mtd[pid] = {}
        self.mtd[pid]['depth'] = 0
        self.mtd[pid]['rstacks'] = [{}]
        self.opt_line = 0
        self.opt_retval = 0
        if opt_line:
            self.opt_line = 1
        if opt_retval:
            self.opt_retval = 1
        self.start_time = time.time()
        self.globaltrace = self.uftrace_entry
        self.returntrace = self.uftrace_exit
        print("# DURATION     TID     FUNCTION")

    def run(self, cmd):
        import __main__
        dict = __main__.__dict__
        self.runctx(cmd, dict, dict)

    def runctx(self, cmd, globals=None, locals=None):
        if globals is None: globals = {}
        if locals is None: locals = {}
        if not self.donothing:
            _settrace(self.globaltrace)
        try:
            exec(cmd, globals, locals)
        finally:
            if not self.donothing:
                _unsettrace()

    def runfunc(self, func, *args, **kw):
        result = None
        if not self.donothing:
            sys.settrace(self.globaltrace)
        try:
            result = func(*args, **kw)
        finally:
            if not self.donothing:
                sys.settrace(None)
        return result

    def get_thread_data(self, pid):
        ppid = os.getppid()
        if not pid in self.mtd:
            self.mtd[pid] = {}
        if not 'depth' in self.mtd[pid]:
            # inherit the depth of its parent pid
            parent_mtd = self.get_thread_data(ppid)
            self.mtd[pid]['depth'] = parent_mtd['depth']
        if not 'rstacks' in self.mtd[pid]:
            # deep copy rstacks from its parent mtd
            parent_mtd = self.get_thread_data(ppid)
            depth = self.mtd[pid]['depth']
            self.mtd[pid]['rstacks'] = copy.deepcopy(parent_mtd['rstacks'])
        return self.mtd[pid]

    def get_ret_stack(self, mtd, depth):
        rstacks = mtd['rstacks']
        return rstacks[depth]

    def uftrace_entry(self, frame, why, arg):
        if why != 'call':
            return None

        pid = os.getpid()
        mtd = self.get_thread_data(pid)
        rstack = self.get_ret_stack(mtd, mtd['depth'])
        code = frame.f_code
        filename = frame.f_globals.get('__file__', None)
        if not filename:
            return None

        if code.co_name == '_unsettrace':
            return None

        #modulename = os.path.basename(filename)
        modulename = _modname(filename)
        if modulename is not None:
            ignore_it = self.ignore.names(filename, modulename)
            if not ignore_it:
                indent = mtd['depth'] * 2
                space = " " * indent
                rstack['start_time'] = time.time()
                outfmt = "            [%6d] | %s%s() {" \
                        % (pid, space, code.co_name)
                print(outfmt)
                mtd['depth'] += 1
                mtd['rstacks'].append({})
                return self.returntrace     # uftrace_exit

    def uftrace_line(self, frame, why, arg):
        lineno = frame.f_lineno
        filename = frame.f_globals.get('__file__', None)
        if not filename:
            return None

        pid = os.getpid()
        mtd = self.get_thread_data(pid)
        rstack = self.get_ret_stack(mtd, mtd['depth'] - 1)
        #modulename = os.path.basename(filename)
        modulename = _modname(filename)
        if modulename is not None:
            ignore_it = self.ignore.names(filename, modulename)
            if not ignore_it:
                elapsed_us = (time.time() - rstack['start_time']) * 1000
                indent = mtd['depth'] * 2
                space = " " * indent
                bname = os.path.basename(filename)
                if bname[-4:] != '.pyc':
                    print(" %7.3f %s [%6d] | %s%s(%d): %s" \
                            % (elapsed_us, "us", pid, space, bname, lineno,
                                linecache.getline(filename, lineno)), end='')
                return None

    def uftrace_exit(self, frame, why, arg):
        if why == 'line' and self.opt_line:
            return self.uftrace_line(frame, why, arg)

        if why != 'return':
            return None

        pid = os.getpid()
        mtd = self.get_thread_data(pid)
        code = frame.f_code
        filename = frame.f_globals.get('__file__', None)
        if not filename:
            return None

        #modulename = os.path.basename(filename)
        modulename = _modname(filename)
        if modulename is not None:
            ignore_it = self.ignore.names(filename, modulename)
            if not ignore_it:
                mtd['depth'] -= 1
                indent = mtd['depth'] * 2
                space = " " * indent

                rstack = self.get_ret_stack(mtd, mtd['depth'])

                del mtd['rstacks'][mtd['depth']]

                duration = (time.time() - rstack['start_time']) * (10 ** 9)
                (time_val, time_unit) = get_time_and_unit(duration)

                retval_fmt = ""
                if self.opt_retval and arg:
                    retval_fmt = " = %s;" % arg
                outfmt = " %7.3f %s [%6d] | %s}%s" \
                    % (time_val, time_unit, pid, space, retval_fmt)
                print(outfmt, "%s/* %s */%s" % (TERM_COLOR_GRAY, code.co_name, TERM_COLOR_RESET))
                return None

def _err_exit(msg):
    sys.stderr.write("%s: %s\n" % (sys.argv[0], msg))
    sys.exit(1)

def main(argv=None):
    import getopt

    if argv is None:
        argv = sys.argv
    try:
        opts, prog_argv = getopt.getopt(argv[1:], "LR",
                                        ["help",
                                         "ignore-module=", "ignore-dir=",
                                         "line", "retval"])

    except getopt.error as msg:
        sys.stderr.write("%s: %s\n" % (sys.argv[0], msg))
        sys.stderr.write("Try `%s --help' for more information\n"
                         % sys.argv[0])
        sys.exit(1)

    ignore_modules = []
    ignore_dirs = []
    opt_line = False
    opt_retval = False

    for opt, val in opts:
        if opt == "--help":
            _usage(sys.stdout)
            sys.exit(0)

        if opt == "-L" or opt == "--line":
            opt_line = True
            continue

        if opt == "-R" or opt == "--retval":
            opt_retval = True
            continue

        if opt == "--ignore-module":
            for mod in val.split(","):
                ignore_modules.append(mod.strip())
            continue

        if opt == "--ignore-dir":
            for s in val.split(os.pathsep):
                s = os.path.expandvars(s)
                # should I also call expanduser? (after all, could use $HOME)

                s = s.replace("$prefix",
                              os.path.join(sys.prefix, "lib",
                                           "python" + sys.version[:3]))
                s = s.replace("$exec_prefix",
                              os.path.join(sys.exec_prefix, "lib",
                                           "python" + sys.version[:3]))
                s = os.path.normpath(s)
                ignore_dirs.append(s)
            continue

        assert 0, "Should never get here"

    # everything is ready
    sys.argv = prog_argv
    progname = prog_argv[0]
    sys.path[0] = os.path.split(progname)[0]

    t = Trace(ignoremods=ignore_modules,
              ignoredirs=ignore_dirs,
              opt_line=opt_line, opt_retval=opt_retval)
    try:
        with open(progname) as fp:
            code = compile(fp.read(), progname, 'exec')
        # try to emulate __main__ namespace as much as possible
        globs = {
            '__file__': progname,
            '__name__': '__main__',
            '__package__': None,
            '__cached__': None,
        }
        t.runctx(code, globs, globs)
    except OSError as err:
        _err_exit("Cannot run file %r because: %s" % (sys.argv[0], err))
    except SystemExit:
        pass

#  Deprecated API
class Ignore(_Ignore):
    def __init__(self, modules=None, dirs=None):
        _warn("The class trace.Ignore is deprecated",
             DeprecationWarning, 2)
        _Ignore.__init__(self, modules, dirs)

if __name__=='__main__':
    main()
