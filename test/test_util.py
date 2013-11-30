from twisted.trial import unittest
from twisted.internet import defer
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.interfaces import IProtocolFactory
from zope.interface import implements

from txtorcon.util import process_from_address, delete_file_or_tree, find_keywords, ip_from_int, find_tor_binary

import os
import tempfile


class FakeState:
    tor_pid = 0


class FakeProtocolFactory:
    implements(IProtocolFactory)

    def doStart(self):
        "IProtocolFactory API"

    def doStop(self):
        "IProtocolFactory API"

    def buildProtocol(self, addr):
        "IProtocolFactory API"
        return None


class TestIPFromInt(unittest.TestCase):

    def test_cast(self):
        self.assertEqual(ip_from_int(0x7f000001), '127.0.0.1')


class TestGeoIpDatabaseLoading(unittest.TestCase):

    def test_bad_geoip_path(self):
        "fail gracefull if a db is missing"
        from txtorcon import util
        self.assertRaises(IOError, util.create_geoip, '_missing_path_')


class TestFindKeywords(unittest.TestCase):

    def test_filter(self):
        "make sure we filter out keys that look like router IDs"
        self.assertEqual(
            find_keywords("foo=bar $1234567890=routername baz=quux".split()),
            {'foo': 'bar',
             'baz': 'quux'})


class TestNetLocation(unittest.TestCase):

    def test_city_fails(self):
        "make sure we don't fail if the city lookup excepts"
        from txtorcon import util
        orig = util.city
        try:

            class Thrower(object):

                def record_by_addr(*args, **kw):
                    raise RuntimeError("testing failure")

            util.city = Thrower()
            nl = util.NetLocation('127.0.0.1')
            self.assertEqual(None, nl.city)

        finally:
            util.city = orig

    def test_no_city_db(self):
        "ensure we lookup from country if we have no city"
        from txtorcon import util
        origcity = util.city
        origcountry = util.country
        try:
            util.city = None
            obj = object()

            class CountryCoder(object):

                def country_code_by_addr(self, ipaddr):
                    return obj

            util.country = CountryCoder()
            nl = util.NetLocation('127.0.0.1')
            self.assertEqual(obj, nl.countrycode)

        finally:
            util.city = origcity
            util.country = origcountry

    def test_no_city_or_country_db(self):
        "ensure we lookup from asn if we have no city or country"
        from txtorcon import util
        origcity = util.city
        origcountry = util.country
        origasn = util.asn
        try:
            util.city = None
            util.country = None

            class Thrower:

                def org_by_addr(*args, **kw):
                    raise RuntimeError("testing failure")

            util.asn = Thrower()
            nl = util.NetLocation('127.0.0.1')
            self.assertEqual('', nl.countrycode)

        finally:
            util.city = origcity
            util.country = origcountry
            util.asn = origasn


class TestProcessFromUtil(unittest.TestCase):

    def setUp(self):
        self.fakestate = FakeState()

    def test_none(self):
        "ensure we do something useful on a None address"
        self.assertEqual(process_from_address(None, 80, self.fakestate), None)

    def test_internal(self):
        "look up the (Tor_internal) PID"
        pfa = process_from_address('(Tor_internal)', 80, self.fakestate)
        # depends on whether you have psutil installed or not, and on
        # whether your system always has a PID 0 process...
        self.assertEqual(pfa, self.fakestate.tor_pid)

    @defer.inlineCallbacks
    def test_real_addr(self):
        ## FIXME should choose a port which definitely isn't used.

        ## it's apparently frowned upon to use the "real" reactor in
        ## tests, but I was using "nc" before, and I think this is
        ## preferable.
        from twisted.internet import reactor
        listener = yield TCP4ServerEndpoint(reactor,
                                            9887).listen(FakeProtocolFactory())

        try:
            pid = process_from_address('0.0.0.0', 9887, self.fakestate)
        finally:
            listener.stopListening()

        self.assertEqual(pid, os.getpid())


class TestDelete(unittest.TestCase):

    def test_delete_file(self):
        (fd, f) = tempfile.mkstemp()
        os.write(fd, 'some\ndata\n')
        os.close(fd)
        self.assertTrue(os.path.exists(f))
        delete_file_or_tree(f)
        self.assertTrue(not os.path.exists(f))

    def test_delete_tree(self):
        d = tempfile.mkdtemp()
        f = open(os.path.join(d, 'foo'), 'w')
        f.write('foo\n')
        f.close()

        self.assertTrue(os.path.exists(d))
        self.assertTrue(os.path.isdir(d))
        self.assertTrue(os.path.exists(os.path.join(d, 'foo')))

        delete_file_or_tree(d)

        self.assertTrue(not os.path.exists(d))
        self.assertTrue(not os.path.exists(os.path.join(d, 'foo')))


class TestFindTor(unittest.TestCase):

    def test_simple_find_tor(self):
        ## just test that this doesn't raise an exception
        find_tor_binary()

    def test_find_tor_globs(self):
        "test searching by globs"
        find_tor_binary(system_tor=False)

    def test_find_tor_unfound(self):
        "test searching by globs"
        self.assertEqual(None, find_tor_binary(system_tor=False, globs=()))
