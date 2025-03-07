#!/usr/bin/env python3

help="""
Trace how an user-supplied packet traverses an iptables ruleset
and the outcome of that traversal

Copyright 2021 Francesco Chemolli <frac at frac.dev>

This software is licensed according to the GNU General Public License
version 3 or later. See the file LICENSE for details.
"""

from argparse import ArgumentParser
import ipaddress
import pprint
import shlex
import sys

class argsparser(ArgumentParser):
    def __init__(self):
        super().__init__(description=help, prog="iptsim")
        self.add_argument('--version', action='version', version='%(prog)s 0.1')
        self.add_argument('--file', '-f', type=str, action='store',
            required=True,
            help='File containing the ruleset from iptables-save')
        self.add_argument('--src', '-s', type=str, required=True,
            help='Source address of the test packet')
        self.add_argument('--dst', '-d', type=str, required=True,
            help='Destination address of the test packet')
        self.add_argument('--proto', '-p', type=str,
            help='Protocol (tcp, udp, ...)')
        self.add_argument('--dport', type=int,
            help='destination port. If proto is tcp or udp, one of sport or dport is required')
        self.add_argument('--sport', type=int,
            help='destination port. If proto is tcp or udp, one of sport or dport is required')
        self.add_argument('--myip', type=str, action='append',
            help='Local address. May be used more than once')

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
            self.add_argument(f"-{letter}", type=str)
        for arg in long_args:
            self.add_argument(arg, type=str)
        self.add_argument('--tcp-flags', nargs='*', type=str)
        self.add_argument('--clamp-mss-to-pmtu', action='store_true')


class packet:
    def __init__(self, argspec):
        self.src = ipaddress.ip_address(argspec.src)
        self.dst = ipaddress.ip_address(argspec.dst)


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
        if spec['s']:
            spec['src'] = ipaddress.ip_network(spec['s'])
        if spec['d']:
            spec['dst'] = ipaddress.ip_network(spec['d'])
        self.spec = spec
    
    def __repr__(self):
        return f'rule[{self.lineno}: {self.spec}]'
    
    # override this in subclasses to perform actions
    # will be invoked if src/dst matches
    #  Returns None or "-" if no action no match
    #  returns self.j if another chain or final action needs to happen
    #  can modify self e.g. for SNAT, DNAT, etc.
    def act(self, pkt: packet):
        return self.j

    def match(self, pkt: packet) -> str:
        print(f'matching {pkt.src},{pkt.dst} in {self.lineno}')
        if self.src and pkt.src and pkt.src not in self.src:
            return None
        if self.dst and pkt.dst and pkt.dst not in self.dst:
            return None
        # TODO: add more conditions
        print(f'*** hit in {self.lineno} -> {self.raw}')
        return self.act(pkt)

class rule_snat(rule):
    def act(self, pkt: packet):
        print(f'SNAT to {self.to_source}')
        pkt.s = self.to_source
        pkt.__init__() # reinit cache

class rule_dnat(rule):
    def act(self, pkt: packet):
        print(f'DNAT to {self.to_destination}')
        pkt.d = self.to_destination
        pkt.__init__() # reinit cache


def buld_rule(rawline: str, parsedline, lineno: int) -> rule:
    rulestable = {
        'SNAT': rule_snat,
        'DNAT': rule_dnat
    }
    if parsedline.j in rulestable:
        return rulestable[parsedline.j](rawline, parsedline, lineno)
    return rule(rawline, parsedline, lineno)

class chain:
    def __init__(self, table, name, action):
        self.table = table
        self.name = name
        self.action = action # one of 'ACCEPT', 'REJECT', '-'
        self.rules = []

    def add_rule(self, rulespec: rule):
        self.rules.append(rulespec)

    def __str__(self):
        return f'chain[{self.name}]({self.action}, {self.rules})'
    
    def __repr__(self):
        return str(self)

    def match(self, packet: packet) -> str:
        for rule in self.rules:
            r = rule.match(packet)
            if r:
                return r

    def _walk(self, tables, pkt) -> str or None:
        t = self.match(pkt)
        if t in {'ACCEPT', 'REJECT', 'DROP', 'MASQUERADE', 'TCPMSS', None}:
            return t
        print(f'recursing into {self.table}.{t}')
        return tables[self.table][t].walk(tables, pkt)
    
    def walk(self, tables, pkt) -> str:
        r = self._walk(tables, pkt)
        if r is None:
            return self.action

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
                tables[table].update( {name: chain(table, name, action)} )
                continue
            if line[0] == '-':  # new rule in chain
                words = shlex.split(line)
                # TODO: move to rules factory with special cases
                rulespec = rule(line, lp.parse_args(words), lineno)
                tables[table][rulespec.A].add_rule(rulespec)
                continue
#    pprint.pprint(tables)
    return tables

        

def main():
    parser = argsparser()
    args = parser.parse_args()
    tables = parse_rules(args.file)
    pkt = packet(args)
    print(f'src: {args.src}')
    print(f'myip: {args.myip}')
    print("**** match **** ")
    # locally-originated packet
    if args.myip and len(args.myip) and pkt.src in args.myip:
        print(tables['mangle']['OUTPUT'].walk(tables, pkt))
        print(tables['nat']['OUTPUT'].walk(tables, pkt))
        print(tables['filter']['OUTPUT'].walk(tables, pkt))
        print(tables['mangle']['POSTROUTING'].walk(tables, pkt))
        print(tables['nat']['POSTROUTING'].walk(tables, pkt))
        return 0
    # packet to this host
    if args.myip and len(args.myip) and pkt.dst in args.myip:
        print(tables['mangle']['PREROUTING'].walk(tables, pkt))
        print(tables['nat']['PREROUTING'].walk(tables, pkt))
        print(tables['mangle']['INPUT'].walk(tables, pkt))
        print(tables['filter']['INPUT'].walk(tables, pkt))
        return 0
    # forwarded packets
    print(tables['mangle']['PREROUTING'].walk(tables, pkt))
    print(tables['nat']['PREROUTING'].walk(tables, pkt))
    print(tables['mangle']['FORWARD'].walk(tables, pkt))
    print(tables['filter']['FORWARD'].walk(tables, pkt))
    print(tables['mangle']['PREROUTING'].walk(tables, pkt))
    print(tables['nat']['PREROUTING'].walk(tables, pkt))
    return 0

sys.exit(main())
