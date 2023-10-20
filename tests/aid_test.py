#! /usr/bin/env python
"""
Unit & functional tests for the Community ID package. Run with something like:

python -m unittest communityid_test
nose2 -C --coverage ../aid --coverage-report term-missing communityid_test

You can also invoke this file directly.
"""
import os
import socket
import struct
import subprocess
import sys
import unittest

try:
    import pylint.epylint
except ImportError:
    pass # Pity!

LOCAL_DIR=os.path.dirname(__file__)
MODULE_DIR=os.path.abspath(os.path.join(LOCAL_DIR, '..'))
sys.path.insert(0, MODULE_DIR)

import aid
import aid.compat

class TestAID(unittest.TestCase):

    def setUp(self):
        self.cids = [
            aid.AID(),
            aid.AID(use_base64=False),
            aid.AID(seed=1),
        ]

    def assertEqualID(self, cft, correct_results):
        """
        Helper for ID string correctness assertion.
        cft is a aid.FlowTuple.
        """
        # Create a list of tuples, each containing a AID
        # instance as first member, and the expected result as the
        # second:
        cid_result_pairs = zip(self.cids, correct_results)

        for cid, correct_res in cid_result_pairs:
            res = cid.calc(cft)
            self.assertEqual(res, correct_res,
                             msg='%s: %s result is %s, should be %s, err: %s'
                             % (cid, cft, res, correct_res, cid.get_error()))

    def verify_full_tuples(self, tuples, high_level_func, proto_num, af_family):
        """
        Verifies for each of the provided flow tuples and expected
        Community ID strings that the computation produces the
        expected result, trying the various supported types for the
        flow tuple coordinates.
        """
        for tpl in tuples:
            ts, srcip, dstip, srcport, dstport = tpl[0], tpl[1], tpl[2], tpl[3], tpl[4]
            expected_aid, aid_without_b64, aid_with_seed_1 = tpl[5], tpl[6], tpl[7]
            aids = tpl[5:]

            # Using the convenience wrapper:
            cft = high_level_func(ts, srcip, dstip, srcport, dstport)
            self.assertEqualID(cft, aids)

            # Using specific protocol number:
            cft = aid.FlowTuple(proto_num, ts, srcip, dstip, srcport, dstport)
            self.assertEqualID(cft, aids)

            # Using packed NBO, as when grabbing from a packet header:
            cft = aid.FlowTuple(
                proto_num,
                ts,
                socket.inet_pton(af_family, srcip),
                socket.inet_pton(af_family, dstip),
                struct.pack('!H', srcport),
                struct.pack('!H', dstport))
            self.assertEqualID(cft, aids)

            # Using a mix, ewww.
            cft = aid.FlowTuple(
                proto_num,
                ts,
                socket.inet_pton(af_family, srcip),
                socket.inet_pton(af_family, dstip),
                srcport, dstport)
            self.assertEqualID(cft,  aids)

            # Using Python 3.3+'s ipaddress types or their 2.x
            # backport:
            try:
                cft = aid.FlowTuple(
                    proto_num,
                    ts,
                    aid.compat.ip_address(srcip),
                    aid.compat.ip_address(dstip),
                    srcport, dstport
                )
                self.assertEqualID(cft,  aids)
            except RuntimeError:
                pass

    def verify_short_tuples(self, tuples, high_level_func, proto_num, af_family):
        """
        Similar to verify_full_tuples, but for the IP-only tuple scenario.
        """

        for tpl in tuples:
            ts, srcip, dstip = tpl[0], tpl[1], tpl[2]
            aids = tpl[3:]
            # Using the convenience wrapper:
            cft = high_level_func(ts, srcip, dstip, proto_num)
            self.assertEqualID(cft, aids)

            # Using specific protocol number:
            cft = aid.FlowTuple(proto_num, ts, srcip, dstip)
            self.assertEqualID(cft, aids)

            # Using packed NBO, as when grabbing from a packet header:
            cft = aid.FlowTuple(
                proto_num,
                ts,
                socket.inet_pton(af_family, srcip),
                socket.inet_pton(af_family, dstip))
            self.assertEqualID(cft, aids)

            # Using a mix, ewww.
            cft = aid.FlowTuple(
                proto_num, ts, srcip, socket.inet_pton(af_family, dstip))
            self.assertEqualID(cft, aids)

            # Using Python 3.3+'s ipaddress types or their 2.x
            # backport:
            try:
                cft = aid.FlowTuple(
                    proto_num,
                    ts,
                    aid.compat.ip_address(srcip),
                    aid.compat.ip_address(dstip))
                self.assertEqualID(cft, aids)
            except RuntimeError:
                pass

    # All of the following tests would be tidier with the DDT module,
    # but I'm reluctant to add third-party dependencies for
    # testing. --cpk
    #
    def test_icmp(self):
        self.verify_full_tuples(
            [
                ['14234568.125489', '192.168.0.89', '192.168.0.1', 8, 0,
                '2:cm8+zVFOJ2b9ropzTEn4ugg4n5E=',
                 '2:726f3ecd514e2766fdae8a734c49f8ba08389f91',
                 '2:glOZwPuOQH7UeZrYwbkxRSPrQ7A='
                 ],

                ['14234568.125489', '192.168.0.1', '192.168.0.89', 0, 8,
                '2:cm8+zVFOJ2b9ropzTEn4ugg4n5E=',
                 '2:726f3ecd514e2766fdae8a734c49f8ba08389f91',
                 '2:glOZwPuOQH7UeZrYwbkxRSPrQ7A=',
                 ],

                # This is correct: message type 20 (experimental) isn't
                # one we consider directional, so the message code ends up
                # in the hash computation, and thus two different IDs result:
                ['14234568.125489', '192.168.0.89', '192.168.0.1', 20, 0,
                '2:F6i0vCAMWZ3/7vfRWjguh+U+mBc=',
                 '2:17a8b4bc200c599dffeef7d15a382e87e53e9817',
                 '2:CF2kexupPNXSMIuECZUn28smQbY=',
                 ],

                ['14234568.125489', '192.168.0.89', '192.168.0.1', 20, 1,
                '2:q7o0rNRuJDJoCb/DCbT3h848Xp0=',
                 '2:abba34acd46e24326809bfc309b4f787ce3c5e9d',
                 '2:oydrqNjjYKjRj7j9VXkXrR7WASs='
                 ],

                # Therefore the following does _not_ get treated as the
                # reverse direction, but _does_ get treated the same as
                # the first two tuples, because for message type 0 the
                # code is currently ignored.
                ['14234568.125489', '192.168.0.1', '192.168.0.89', 0, 20,
                 '2:cm8+zVFOJ2b9ropzTEn4ugg4n5E=',
                 '2:726f3ecd514e2766fdae8a734c49f8ba08389f91',
                 '2:glOZwPuOQH7UeZrYwbkxRSPrQ7A='
                 ],
            ],
            aid.FlowTuple.make_icmp,
            aid.PROTO_ICMP,
            socket.AF_INET)


    #
    def test_icmp6(self):
        self.verify_full_tuples(
            [
                ['14.125489', 'fe80::200:86ff:fe05:80da', 'fe80::260:97ff:fe07:69ea', 135, 0,
                 '2:G52qOZ/Xl1IQatX7QFj1xiF9zu0=',
                 '2:1b9daa399fd79752106ad5fb4058f5c6217dceed',
                 '2:TR3VmEV+YrJoSxUp91WrSBvp+94='],

                ['14.125489', 'fe80::260:97ff:fe07:69ea', 'fe80::200:86ff:fe05:80da', 136, 0,
                '2:G52qOZ/Xl1IQatX7QFj1xiF9zu0=',
                '2:1b9daa399fd79752106ad5fb4058f5c6217dceed',
                '2:TR3VmEV+YrJoSxUp91WrSBvp+94='],


                ['14.125489', '3ffe:507:0:1:260:97ff:fe07:69ea', '3ffe:507:0:1:200:86ff:fe05:80da', 3, 0,
                '2:RMrI795nS5JuNlQg09BReQ83tOM=',
                '2:44cac8efde674b926e365420d3d051790f37b4e3',
                '2:zVGE0p0rqzfBh60XCsEj7Esunus='],


                ['14.125489', '3ffe:507:0:1:200:86ff:fe05:80da', '3ffe:507:0:1:260:97ff:fe07:69ea', 3, 0,
                '2:q/0YO81FIf88HRBiEggjZt10f9w=',
                '2:abfd183bcd4521ff3c1d106212082366dd747fdc',
                '2:vZvndwCMoeqoaPkyOrcphZ9SxCM='],
            ],
            aid.FlowTuple.make_icmp6,
            aid.PROTO_ICMP6,
            socket.AF_INET6)

    def test_sctp(self):
        self.verify_full_tuples(
            [
                ['14.125489', '192.168.170.8', '192.168.170.56', 7, 80,
                '2:RiAuFagiMtzFGK9YcfeuvUui8Rc=',
                 '2:46202e15a82232dcc518af5871f7aebd4ba2f117',
                 '2:F+w4BmjStIy6NBS5KU50q56KjS0=', ],

                ['14.125489', '192.168.170.56', '192.168.170.8', 80, 7,
                '2:RiAuFagiMtzFGK9YcfeuvUui8Rc=',
                 '2:46202e15a82232dcc518af5871f7aebd4ba2f117',
                 '2:F+w4BmjStIy6NBS5KU50q56KjS0='],
            ],
            aid.FlowTuple.make_sctp,
            aid.PROTO_SCTP,
            socket.AF_INET)

    def test_tcp(self):
        self.verify_full_tuples(
            [
                ['14.125489','128.232.110.120', '66.35.250.204', 34855, 80,
                 '2:HWVGag5ileXtZaijMED7wFK2Wnw=',
                 '2:1d65466a0e6295e5ed65a8a33040fbc052b65a7c',
                 '2:UlZmMdor6J1xeG2ufTBCLvORHWk='],

                ['14.125489','66.35.250.204', '128.232.110.120', 80, 34855,
                '2:HWVGag5ileXtZaijMED7wFK2Wnw=',
                '2:1d65466a0e6295e5ed65a8a33040fbc052b65a7c',
                '2:UlZmMdor6J1xeG2ufTBCLvORHWk='],

                # Verify https://github.com/corelight/pycommunityid/issues/3
                ['142548.12','10.0.0.1', '10.0.0.2', 10, 11569,
                 '2:NGw+yq/J+dtY5lWAXVjAOPhiZDk=',
                 '2:346c3ecaafc9f9db58e655805d58c038f8626439',
                 '2:DpBjUG3upN0w1n4I6uOqY3r9sf8='
                 ],
            ],
            aid.FlowTuple.make_tcp,
            aid.PROTO_TCP,
            socket.AF_INET)

    def test_udp(self):
        # the three hashes used for testing are 1 for
        # aid.AID(), 1 without base 64 and one with seed=1
        self.verify_full_tuples(
            [
                [
                 '1601998366.806331','192.168.1.52', '8.8.8.8', 54585, 53,
                 '2:rEQ2fCKqQlrXOHmljIGNL0W7mes=',
                 '2:ac44367c22aa425ad73879a58c818d2f45bb99eb',
                 '2:Wv56hNj9UvXtDVsCe3UwB0+nGNM='
                 ],
                [
                    '14.125489','8.8.8.8', '192.168.1.52', 53, 54585,
                    '2:MFrVR5TU1GlRA1eJE/RpqFNCPd0=',
                    '2:305ad54794d4d4695103578913f469a853423ddd',
                    '2:UfdfqxbJ/Y2j+QW7x0yzQbwHTno='
                ]

            ],
            aid.FlowTuple.make_udp,
            aid.PROTO_UDP,
            socket.AF_INET)

    def test_ip(self):
        self.verify_short_tuples(
            [
                ['1601998366.806331', '10.1.24.4', '10.1.12.1',
                 '2:f/jCaTaql4i2dkiYbPbpRQA5lWg=',
                 '2:7ff8c26936aa9788b67648986cf6e94500399568',
                 '2:QM69eDk9KKO7pt4fCHRR3WoQ5Ds='],

                ['160166.806', '10.1.12.1', '10.1.24.4',
                 '2:QszWW4WqKjNZRMQ6ZdzYHYwTi84=',
                '2:42ccd65b85aa2a335944c43a65dcd81d8c138bce',
                 '2:lDb1HTeX/VTrraT295C2ZD/hTv8='],
            ],
            aid.FlowTuple.make_ip,
            46, socket.AF_INET)

    def test_inputs(self):
        ts = '14.125489'
        # Need protocol
        with self.assertRaises(aid.FlowTupleError):
            tpl = aid.FlowTuple(
                None, ts, '1.2.3.4', '5.6.7.8')

        # Need both IP addresses
        with self.assertRaises(aid.FlowTupleError):
            aid.FlowTuple(
                aid.PROTO_TCP, ts, '1.2.3.4', None)
        with self.assertRaises(aid.FlowTupleError):
            aid.FlowTuple(
                aid.PROTO_TCP, ts, None, '5.6.7.8')

        # Need parseable IP addresses
        with self.assertRaises(aid.FlowTupleError):
            aid.FlowTuple(
                aid.PROTO_TCP, ts, 'ohdear.com', '5.6.7.8')
        with self.assertRaises(aid.FlowTupleError):
            aid.FlowTuple(
                aid.PROTO_TCP, ts, '1.2.3.4', 'ohdear.com')

        # Need two valid ports
        with self.assertRaises(aid.FlowTupleError):
            aid.FlowTuple(
                aid.PROTO_TCP, ts, '1.2.3.4', '5.6.7.8', 23, None)
        with self.assertRaises(aid.FlowTupleError):
            aid.FlowTuple(
                aid.PROTO_TCP, ts, '1.2.3.4', '5.6.7.8', None, 23)
        with self.assertRaises(aid.FlowTupleError):
            aid.FlowTuple(
                aid.PROTO_TCP, ts, '1.2.3.4', '5.6.7.8', "23/tcp", 23)
        with self.assertRaises(aid.FlowTupleError):
            aid.FlowTuple(
                aid.PROTO_TCP, ts, '1.2.3.4', '5.6.7.8', 23, "23/tcp")

        # Need ports with port-enabled protocol
        with self.assertRaises(aid.FlowTupleError):
            tpl = aid.FlowTuple(
                aid.PROTO_TCP, ts, '1.2.3.4', '5.6.7.8')

    @unittest.skipIf(sys.version_info[0] < 3, 'not supported in Python 2.x')
    def test_inputs_py3(self):
        # Python 3 allows us to distinguish strings and byte sequences,
        # and the following test only applies to it.
        with self.assertRaises(aid.FlowTupleError):
            aid.FlowTuple(
                aid.PROTO_TCP, '14234568.125489','1.2.3.4', '5.6.7.8', 23, "80")

    def test_get_proto(self):
        self.assertEqual(aid.get_proto(23), 23)
        self.assertEqual(aid.get_proto("23"), 23)
        self.assertEqual(aid.get_proto("tcp"), 6)
        self.assertEqual(aid.get_proto("TCP"), 6)
        self.assertEqual(aid.get_proto("23/tcp"), None)



if __name__ == '__main__':
    unittest.main()
