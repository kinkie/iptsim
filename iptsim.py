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
    # atts: raw, lineno, action, rulespec(hash of declaration)
    def __init__(self, rawline, parsedline, lineno):
        self.raw = rawline
        self.action = parsedline.j;
        self.spec = vars(parsedline)
        self.lineno = lineno
        self.chain = self.spec['A'][0]
    
    def __repr__(self):
        return f'rule[line={self.lineno}, action={self.action}]'


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
    # print(f'parse_rules({filename})')
    tables={}
    lp = lineparser()
    with open(filename, 'r') as rulefile:
        lineno = 0
        table = ''
        for line in rulefile:
            lineno = lineno + 1
            line = line[0:-1]
            # print(f'line: {line}')
            if line[0] == '*':  # define a new table and switch to it
                table = line[1:]
                # print(f'new table: {table}')
                tables[table] = {}
                continue
            if line[0] == ':':  # new chain with default rule
                (name, action, rest) = line[1:].split(' ')
                # print(f'new chain {name}, action {action}')
                tables[table].update( {name: chain(name,action)} )
                continue
            if line[0] == '-':  # new rule in chain
                words = shlex.split(line)
                # print(f'new rule: {words}')
                rulespec = rule(line, lp.parse_args(words), lineno)
                # print(f'rulespec: {rulespec}')
                tables[table][rulespec.chain].add_rule(rulespec)
                continue
    pprint.pprint(tables)

def main():
    parser = argsparser()
    args = parser.parse_args()
    # print(f'parsed: {args}')
    parse_rules(args.file[0])
    return 0

sys.exit(main())
