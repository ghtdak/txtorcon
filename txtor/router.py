from util import NetLocation
from zope.interface import Interface


class IRouterContainer(Interface):

    def router_from_id(self, routerid):
        "Return a router by its ID."


def hexIdFromHash(hash):
    "From the base-64 encoded hashes Tor uses, this produces the longer hex-encoded hashes."
    return '$' + (hash + "=").decode("base64").encode("hex").upper()


class PortRange(object):
    "Represents a range of ports for Router policies."

    def __init__(self, a, b):
        self.min = a
        self.max = b

    def __cmp__(self, b):
        if b >= self.min and b <= self.max:
            return 0
        return 1

    def __str__(self):
        return "%d-%d" % (self.min, self.max)


class Router(object):
    """
    Represents a Tor Router. The controller you pass in is really only
    used to do get_info calls for ip-to-country/IP in case the
    NetLocation stuff fails to find a country.

    After an .update() call, the id_hex attribute contains a
    hex-encoded long hash (suitable, for example, to use in a ns/id/*
    call).

    After a .set_policy() you may call accepts_port() to find out if
    the router will accept a given port. This works with the reject or
    accept based policies.
    """

    def __init__(self, controller):
        self.controller = controller
        self.flags = []
        self.bandwidth = 0
        self.name_is_unique = False
        self.accepted_ports = None
        self.rejected_ports = None
        self.id_hex = None
        self.location = NetLocation('0.0.0.0')

    def update(self, name, idhash, orhash, modified, ip, orport, dirport):
        self.name = name
        self.id_hash = idhash
        self.or_hash = orhash
        self.modified = modified
        self.ip = ip
        self.or_port = orport
        self.dir_port = dirport
        self.location = NetLocation(self.ip)
        if self.location.countrycode is None:
            ## see if Tor is magic and knows more...
            self.controller.get_info_raw('ip-to-country/' +
                                         self.ip).addCallback(self.set_country)

        self.id_hex = hexIdFromHash(self.id_hash)

    def set_flags(self, flags):
        """
        It might be nice to make flags not a list of strings. This is
        made harder by the control-spec: ``I{...controllers MUST tolerate
        unrecognized flags and lines...}''

        There is some current work in Twisted for open-ended constants
        (enums) support however, it seems.
        """
        self.flags = map(lambda x: x.lower(), flags)
        self.name_is_unique = 'named' in self.flags

    def set_bandwidth(self, bw):
        self.bandwidth = bw

    def set_policy(self, args):
        word = args[0]
        if word == 'reject':
            self.accepted_ports = None
            self.rejected_ports = []
            target = self.rejected_ports

        elif word == 'accept':
            self.accepted_ports = []
            self.rejected_ports = None
            target = self.accepted_ports

        else:
            raise Exception("Don't understand policy word \"%s\"" % word)

        for port in args[1].split(','):
            if '-' in port:
                (a, b) = port.split('-')
                target.append(PortRange(int(a), int(b)))
            else:
                target.append(int(port))

    def accepts_port(self, port):
        if self.rejected_ports is None and self.accepted_ports is None:
            raise Exception("set_policy hasn't been called yet")

        if self.rejected_ports:
            for x in self.rejected_ports:
                if port == x:
                    return False
            return True

        for x in self.accepted_ports:
            if port == x:
                return True
        return False

    def get_policy(self):
        "return a string describing the policy"
        if self.accepted_ports:
            ports = 'accept '
            target = self.accepted_ports
        else:
            ports = 'reject '
            target = self.rejected_ports

        if target is None:
            return ''

        last = None
        for x in target:
            ports = ports + str(x) + ','
        return ports[:-1]

    def set_country(self, c):
        self.location.countrycode = c[:-3].split('=')[1].strip().upper()

    def __repr__(self):
        n = self.id_hex
        if self.name_is_unique:
            n = self.name
        return "<Router %s %s %s>" % (n, self.location.countrycode,
                                      self.get_policy())
