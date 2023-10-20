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
    # def test_icmp(self):
    #     self.verify_full_tuples(
    #         [
    #             ['192.168.0.89', '192.168.0.1', 8, 0,
    #              '1:X0snYXpgwiv9TZtqg64sgzUn6Dk=',
    #              '1:5f4b27617a60c22bfd4d9b6a83ae2c833527e839',
    #              '1:03g6IloqVBdcZlPyX8r0hgoE7kA='],
    #
    #             ['192.168.0.1', '192.168.0.89', 0, 8,
    #              '1:X0snYXpgwiv9TZtqg64sgzUn6Dk=',
    #              '1:5f4b27617a60c22bfd4d9b6a83ae2c833527e839',
    #              '1:03g6IloqVBdcZlPyX8r0hgoE7kA='],
    #
    #             # This is correct: message type 20 (experimental) isn't
    #             # one we consider directional, so the message code ends up
    #             # in the hash computation, and thus two different IDs result:
    #             ['192.168.0.89', '192.168.0.1', 20, 0,
    #              '1:3o2RFccXzUgjl7zDpqmY7yJi8rI=',
    #              '1:de8d9115c717cd482397bcc3a6a998ef2262f2b2',
    #              '1:lCXHHxavE1Vq3oX9NH5ladQg02o='],
    #
    #             ['192.168.0.89', '192.168.0.1', 20, 1,
    #              '1:tz/fHIDUHs19NkixVVoOZywde+I=',
    #              '1:b73fdf1c80d41ecd7d3648b1555a0e672c1d7be2',
    #              '1:Ie3wmFyxiEyikbsbcO03d2nh+PM='],
    #
    #             # Therefore the following does _not_ get treated as the
    #             # reverse direction, but _does_ get treated the same as
    #             # the first two tuples, because for message type 0 the
    #             # code is currently ignored.
    #             ['192.168.0.1', '192.168.0.89', 0, 20,
    #              '1:X0snYXpgwiv9TZtqg64sgzUn6Dk=',
    #              '1:5f4b27617a60c22bfd4d9b6a83ae2c833527e839',
    #              '1:03g6IloqVBdcZlPyX8r0hgoE7kA='],
    #         ],
    #         aid.FlowTuple.make_icmp,
    #         aid.PROTO_ICMP,
    #         socket.AF_INET)
    #
    #
    #
    # def test_icmp6(self):
    #     self.verify_full_tuples(
    #         [
    #             ['fe80::200:86ff:fe05:80da', 'fe80::260:97ff:fe07:69ea', 135, 0,
    #              '1:dGHyGvjMfljg6Bppwm3bg0LO8TY=',
    #              '1:7461f21af8cc7e58e0e81a69c26ddb8342cef136',
    #              '1:kHa1FhMYIT6Ym2Vm2AOtoOARDzY='],
    #
    #             ['fe80::260:97ff:fe07:69ea', 'fe80::200:86ff:fe05:80da', 136, 0,
    #              '1:dGHyGvjMfljg6Bppwm3bg0LO8TY=',
    #              '1:7461f21af8cc7e58e0e81a69c26ddb8342cef136',
    #              '1:kHa1FhMYIT6Ym2Vm2AOtoOARDzY='],
    #
    #             ['3ffe:507:0:1:260:97ff:fe07:69ea', '3ffe:507:0:1:200:86ff:fe05:80da', 3, 0,
    #              '1:NdobDX8PQNJbAyfkWxhtL2Pqp5w=',
    #              '1:35da1b0d7f0f40d25b0327e45b186d2f63eaa79c',
    #              '1:OlOWx9psIbBFi7lOCw/4MhlKR9M='],
    #
    #             ['3ffe:507:0:1:200:86ff:fe05:80da', '3ffe:507:0:1:260:97ff:fe07:69ea', 3, 0,
    #              '1:/OGBt9BN1ofenrmSPWYicpij2Vc=',
    #              '1:fce181b7d04dd687de9eb9923d66227298a3d957',
    #              '1:Ij4ZxnC87/MXzhOjvH2vHu7LRmE='],
    #         ],
    #         aid.FlowTuple.make_icmp6,
    #         aid.PROTO_ICMP6,
    #         socket.AF_INET6)
    #
    # def test_sctp(self):
    #     self.verify_full_tuples(
    #         [
    #             ['192.168.170.8', '192.168.170.56', 7, 80,
    #              '1:jQgCxbku+pNGw8WPbEc/TS/uTpQ=',
    #              '1:8d0802c5b92efa9346c3c58f6c473f4d2fee4e94',
    #              '1:Y1/0jQg6e+I3ZwZZ9LP65DNbTXU='],
    #
    #             ['192.168.170.56', '192.168.170.8', 80, 7,
    #              '1:jQgCxbku+pNGw8WPbEc/TS/uTpQ=',
    #              '1:8d0802c5b92efa9346c3c58f6c473f4d2fee4e94',
    #              '1:Y1/0jQg6e+I3ZwZZ9LP65DNbTXU='],
    #         ],
    #         aid.FlowTuple.make_sctp,
    #         aid.PROTO_SCTP,
    #         socket.AF_INET)
    #
    # def test_tcp(self):
    #     self.verify_full_tuples(
    #         [
    #             ['128.232.110.120', '66.35.250.204', 34855, 80,
    #              '1:LQU9qZlK+B5F3KDmev6m5PMibrg=',
    #              '1:2d053da9994af81e45dca0e67afea6e4f3226eb8',
    #              '1:3V71V58M3Ksw/yuFALMcW0LAHvc='],
    #
    #             ['66.35.250.204', '128.232.110.120', 80, 34855,
    #              '1:LQU9qZlK+B5F3KDmev6m5PMibrg=',
    #              '1:2d053da9994af81e45dca0e67afea6e4f3226eb8',
    #              '1:3V71V58M3Ksw/yuFALMcW0LAHvc='],
    #
    #             # Verify https://github.com/corelight/pycommunityid/issues/3
    #             ['10.0.0.1', '10.0.0.2', 10, 11569,
    #              '1:SXBGMX1lBOwhhoDrZynfROxnhnM=',
    #              '1:497046317d6504ec218680eb6729df44ec678673',
    #              '1:HmBRGR+fUyXF4t8WEtal7Y0gEAo='],
    #         ],
    #         aid.FlowTuple.make_tcp,
    #         aid.PROTO_TCP,
    #         socket.AF_INET)

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

    # def test_inputs(self):
    #     # Need protocol
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             None, '1.2.3.4', '5.6.7.8')
    #
    #     # Need both IP addresses
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, '1.2.3.4', None)
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, None, '5.6.7.8')
    #
    #     # Need parseable IP addresses
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, 'ohdear.com', '5.6.7.8')
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, '1.2.3.4', 'ohdear.com')
    #
    #     # Need two valid ports
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, '1.2.3.4', '5.6.7.8', 23, None)
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, '1.2.3.4', '5.6.7.8', None, 23)
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, '1.2.3.4', '5.6.7.8', "23/tcp", 23)
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, '1.2.3.4', '5.6.7.8', 23, "23/tcp")
    #
    #     # Need ports with port-enabled protocol
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, '1.2.3.4', '5.6.7.8')
    #
    # @unittest.skipIf(sys.version_info[0] < 3, 'not supported in Python 2.x')
    # def test_inputs_py3(self):
    #     # Python 3 allows us to distinguish strings and byte sequences,
    #     # and the following test only applies to it.
    #     with self.assertRaises(aid.FlowTupleError):
    #         tpl = aid.FlowTuple(
    #             aid.PROTO_TCP, '1.2.3.4', '5.6.7.8', 23, "80")
    #
    # def test_get_proto(self):
    #     self.assertEqual(aid.get_proto(23), 23)
    #     self.assertEqual(aid.get_proto("23"), 23)
    #     self.assertEqual(aid.get_proto("tcp"), 6)
    #     self.assertEqual(aid.get_proto("TCP"), 6)
    #     self.assertEqual(aid.get_proto("23/tcp"), None)
#
# class LintCommunityID(unittest.TestCase):
#
#     def setUp(self):
#         if 'pylint.epylint' not in sys.modules:
#             self.skipTest('pylint module not available')
#
#     def test_linting(self):
#         rcfile = os.path.join(LOCAL_DIR, 'pylint.rc')
#         (out, _) = pylint.epylint.py_run('aid --rcfile=' + rcfile, return_std=True)
#
#         for line in out.getvalue().splitlines():
#             if line.find('Your code has been') > 0:
#                 print('\n' + line.strip())
#                 break
#
#         self.assertTrue(out.getvalue().find(' error ') < 0,
#                         msg='Pylint error: ' + out.getvalue())

#
# class TestCommands(unittest.TestCase):
#
#     def setUp(self):
#         # Adjust the environment so it prioritizes our local module
#         # tree. This also makes the tests work before the module is
#         # installed.
#         self.env = os.environ.copy()
#
#         try:
#             ppath = self.env['PYTHONPATH']
#             ppath = MODULE_DIR + os.pathsep + ppath
#         except KeyError:
#             ppath = MODULE_DIR
#
#         self.env['PYTHONPATH'] = ppath
#
#     def _scriptpath(self, scriptname):
#         return os.path.abspath(os.path.join(LOCAL_DIR, '..', 'scripts', scriptname))
#
#     def _testfilepath(self, testfile):
#         return os.path.abspath(os.path.join(LOCAL_DIR, testfile))
#
#     def test_communityid(self):
#         out = subprocess.check_output(
#             [self._scriptpath('all_id.py'), 'tcp', '10.0.0.1', '10.0.0.2', '10', '20'],
#             env=self.env)
#         self.assertEqual(out, b'1:9j2Dzwrw7T9E+IZi4b4IVT66HBI=\n')
#
#     def test_communityid_verbose(self):
#         out = subprocess.check_output(
#             [self._scriptpath('all_id.py'), '-vv', 'tcp', '10.0.0.1', '10.0.0.2', '10', '20'],
#             env=self.env, stderr=subprocess.STDOUT)
#         self.assertEqual(out, b"""INFO     CommunityID for 10.0.0.1 10 -> 10.0.0.2 20, proto 6, ordered:
# INFO     | seed    00:00
# INFO     | ipaddr  0a:00:00:01
# INFO     | ipaddr  0a:00:00:02
# INFO     | proto   06
# INFO     | padding 00
# INFO     | port    00:0a
# INFO     | port    00:14
# 1:9j2Dzwrw7T9E+IZi4b4IVT66HBI=
# """)
#



if __name__ == '__main__':
    unittest.main()
