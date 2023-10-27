#! /usr/bin/env python
"""
This script lets you compute Community ID values for specific flow tuples.
You provide the tuple parts, it provides the ID.
"""
import abc
import argparse
import logging
import sys

import aid_hash

class TupleParser:
    @abc.abstractmethod
    def parse(self, parts):
        """
        Parses the given line parts list into a FlowTuple. Returns
        either a pair (FlowTuple instance, None) if successful, or
        (None, error) with an error string message in case of
        problems.
        """
        return None, None

class DefaultParser(TupleParser):
    """
    Our default parser wants the protocol first, then the
    saddr/daddr/sport/dport tuple, with the ports being optional.
    """
    def parse(self, parts):
        num_parts = len(parts)

        if num_parts not in [3, 5]:
            return None, 'Need either 3 or 5 tuple components'

        proto = aid_hash.get_proto(parts[0])
        if proto is None:
            return None, 'Could not parse IP protocol number'

        sport, dport = None, None

        if num_parts == 5:
            try:
                sport, dport = int(parts[3]), int(parts[4])
            except ValueError:
                return None, 'Could not parse port numbers'

            if (not aid_hash.FlowTuple.is_port(sport) or
                not aid_hash.FlowTuple.is_port(dport)):
                return None, 'Could not parse port numbers'

        try:
            return aid_hash.FlowTuple(
                proto, parts[1], parts[2], sport, dport), None
        except aid_hash.FlowTupleError as err:
            return None, repr(err)

class ZeekLogsParser(TupleParser):
    """
    In Zeek's logs the field order is saddr/sport/daddr/dport/proto.
    This parser simplifies cut'n'paste of those log parts. This
    assumes Zeek logs for 5-tuple flow identifiers. If you encounter a
    need for 3-tuple ones, please file a ticket.
    """
    def parse(self, parts):
        if len(parts) != 5:
            return None, 'Need 5-part tuple when parsing Zeek logs'

        proto = aid_hash.get_proto(parts[4])
        if proto is None:
            return None, 'Could not parse IP protocol number'

        try:
            sport, dport = int(parts[1]), int(parts[3])
        except ValueError:
            return None, 'Could not parse port numbers'

        if not (aid_hash.FlowTuple.is_ipaddr(parts[0]) and
                aid_hash.FlowTuple.is_port(sport) and
                aid_hash.FlowTuple.is_ipaddr(parts[2]) and
                aid_hash.FlowTuple.is_port(dport)):
            return None, 'Need two IP addresses and port numbers'

        try:
            return aid_hash.FlowTuple(
                proto, parts[0], parts[2], sport, dport), None
        except aid_hash.FlowTupleError as err:
            return None, repr(err)

def main():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="""Community ID calculator

This calculator prints the Community ID value for a given tuple
to stdout. It supports the following formats for the tuple:

  [protocol] [src address] [dst address]
  [protocol] [src address] [dst address] [src port] [dst port]
  [src address] [src port] [dst address] [dst port] [protocol]

The protocol is either a numeric IP protocol number, or one of
the constants "icmp", "icmp6", "tcp", "udp", or "sctp". Case
does not matter.
""")
    parser.add_argument('--seed', type=int, default=0, metavar='NUM',
                        help='Seed value for hash operations')
    parser.add_argument('--no-base64', action='store_true', default=False,
                        help="Don't base64-encode the SHA1 binary value")
    parser.add_argument('--verbose', '-v', action='count', default=0,
                        help=('Enable verbose output. Use multiple times '
                              'for more output (e.g. -vvv).'))
    parser.add_argument('flowtuple', nargs=argparse.REMAINDER,
                        help='Flow tuple, in one of the forms described above')
    args = parser.parse_args()

    if not args.flowtuple:
        sys.stderr.write('Need flow tuple as additional arguments.\n')
        return 1

    if args.verbose > 0:
        formatter = logging.Formatter('%(levelname)-8s %(message)s')
        handler = logging.StreamHandler()
        handler.setFormatter(formatter)

        if args.verbose == 1:
            aid_hash.LOG.setLevel(logging.WARNING)
        elif args.verbose == 2:
            aid_hash.LOG.setLevel(logging.INFO)
        elif args.verbose >= 3:
            aid_hash.LOG.setLevel(logging.DEBUG)

        aid_hash.LOG.addHandler(handler)

    commid = aid_hash.AID(args.seed, not args.no_base64)

    for parser in (DefaultParser(), ZeekLogsParser()):
        tpl, msg = parser.parse(args.flowtuple)
        if tpl is None:
            aid_hash.LOG.debug(
                '%s failure: %s\n' % (parser.__class__.__name__, msg))
            continue

        res = commid.calc(tpl)
        if res is None:
            sys.stderr.write(commid.get_error() + '\n')
            return 1

        print(res)
        return 0

    sys.stderr.write('Error in tuple string %s.\n' % args.flowtuple)
    return 1

if __name__ == '__main__':
    sys.exit(main())
