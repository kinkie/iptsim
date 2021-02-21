#!/usr/bin/python3

help="""
Trace how an user-supplied packet traverses an iptables ruleset
and the outcome of that traversal

Copyright 2021 Francesco Chemolli <frac at frac.dev>

This software is licensed according to the GNU General Public License
version 3 or later. See the file LICENSE for details.
"""

from argparse import ArgumentParser
import json
import pprint
import shlex
import sys

class argsparser(ArgumentParser):
    def __init__(self):
        super().__init__(description=help, prog="iptsim")
        self.add_argument('--version', action='version', version='%(prog)s 0.1')
        self.add_argument('--file', '-f', nargs=1, type=str, action='store',
            required=True,
            help='File containing the ruleset from iptables-save')

class lineparser(ArgumentParser):
    def __init__(self):
        super().__init__()
        letter_args = 'Aimjsdop'
        long_args = ['--to-source', '--to-destination', '--comment',
            '--dport', '--set-xmark', '--espspi', '--sport', '--dir',
            '--pol', '--proto', '--ctstate', '--reject-with', '--limit',
            '--limit-burst', '--icmp-type', 
            ]
        for letter in letter_args:
            self.add_argument(f"-{letter}", nargs=1, type=str)
        for arg in long_args:
            self.add_argument(arg, nargs=1, type=str)
        self.add_argument('--tcp-flags', nargs='*', type=str)
        self.add_argument('--clamp-mss-to-pmtu', action='store_true')

class rule:
    def __getattr__(self, name: str):
        if name in self.spec:
            return self.spec[name]
        return None            

    # atts: raw, lineno, action, rulespec(hash of declaration)
    def __init__(self, rawline, parsedline, lineno):
        self.lineno = lineno
        self.raw = rawline
        spec = vars(parsedline)
        for i in spec:
            if isinstance(spec[i], list) and len(spec[i]) == 1:
                spec[i] = spec[i][0]
        self.spec = spec
    
    def __repr__(self):
        return f'rule[{self.lineno}: {self.spec}]'


class chain:
    def __init__(self, name, action):
        self.name=name
        self.action=action # one of 'ACCEPT', 'REJECT', '-'
        self.rules=[]

    def add_rule(self, rulespec: rule):
        self.rules.append(rulespec)

    def __str__(self):
        return f'chain[{self.name}]({self.action}, {self.rules})'
    
    def __repr__(self):
        return str(self)


# representation of iptables is:
# { tablename : { chainname : instanceof(chain) } }
def parse_rules(filename):
    "returns an internal representation of iptables"
    tables={}
    lp = lineparser()
    with open(filename, 'r') as rulefile:
        lineno = 0
        table = ''
        for line in rulefile:
            lineno = lineno + 1
            line = line[0:-1]
            if line[0] == '*':  # define a new table and switch to it
                table = line[1:]
                tables[table] = {}
                continue
            if line[0] == ':':  # new chain with default rule
                (name, action, rest) = line[1:].split(' ')
                tables[table].update( {name: chain(name,action)} )
                continue
            if line[0] == '-':  # new rule in chain
                words = shlex.split(line)
                rulespec = rule(line, lp.parse_args(words), lineno)
                tables[table][rulespec.A].add_rule(rulespec)
                continue
    pprint.pprint(tables)

def main():
    parser = argsparser()
    args = parser.parse_args()
    parse_rules(args.file[0])
    return 0

sys.exit(main())
