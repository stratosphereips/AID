AID
=============

This package provides modified Python implementation of the open
[Community ID](https://github.com/corelight/community-id-spec)
flow hashing standard that takes into consideration the flow timestamp.

It supports Python versions 2.7+ (for not much longer) and 3+.

![example foobar](https://github.com/corelight/pycommunityid/actions/workflows/python.yaml/badge.svg)

Installation
------------

This package is available [on PyPI](https://pypi.org/project/communityid/), therefore:

    pip install aid_hash

To install locally from a git clone, you can use also use pip, e.g. by saying

    pip install -U .


Usage
-----


The API breaks the computation into two steps: (1) creation of a flow

tuple object, (2) computation of the Community ID string on this

object. It supports various input types in order to accommodate

network byte order representations of flow endpoints, high-level ASCII,

and ipaddress objects.


Here's what it looks like:

    
    import aid_hash
    
    tpl = aid.FlowTuple.make_tcp('14.125487','127.0.0.1', '10.0.0.1', 1234, 80)

    aid =  aid_hash.AID()

    print(aid.calc(tpl))

This will print 2:7RJA0SqvF3nbfatPoP1dkZnVvWw=.


CommunityID vs AID
-----
AID is a modified version of Zeek's CommunityID. 
The main purpose of it is to avoid the collisions
caused when CID groups flows that happened in different days together because they have common 
srcip/dstip srcport/dstport and proto

for example:

if there's a flow from IP1:port1 -> IP2:port2 at 1AM 10/10/2023, 
it will have the same community ID as a flow from IP1:port1 -> IP2:port2 at 9PM 10/10/2023 or even a week after.
which means that entirely different flows will have the same cid.

The major difference is that AID
take into consideration the timestamp of the flow. 
AID matches exact flows accross different monitors instead of correlating them.


Testing
-------

The package includes a unittest testsuite in the `tests` directory
that runs without installation of the module. After changing into that
folder you can invoke it e.g. via

    python3 -m unittest tests/aid_test.py    



Acknowledgments
------

This is a fork of Zeek's Community ID, the code was originally written by Christian Kreibich @ckreibich

