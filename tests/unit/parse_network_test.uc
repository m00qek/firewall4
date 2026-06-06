'use strict';

import { describe, it, assert, equals, contains, beforeEach, afterEach } from 'utest';

const fw4 = require('fw4');

describe('fw4.parse_subnet', () => {
	it('parses an IPv4 host address', () => {
		assert.match(
			equals([contains({ family: 4, addr: '192.168.1.1', bits: 32 })]),
			fw4.parse_subnet('192.168.1.1')
		);
	});

	it('parses an IPv4 CIDR block', () => {
		assert.match(
			equals([contains({ family: 4, addr: '10.0.0.0', bits: 8 })]),
			fw4.parse_subnet('10.0.0.0/8')
		);
	});

	it('parses an IPv4 range', () => {
		assert.match(
			equals([contains({ family: 4, addr: '192.168.1.1', addr2: '192.168.1.10', range: true })]),
			fw4.parse_subnet('192.168.1.1-192.168.1.10')
		);
	});

	it('parses an IPv6 host address', () => {
		assert.match(
			equals([contains({ family: 6, addr: '::1', bits: 128 })]),
			fw4.parse_subnet('::1')
		);
	});

	it('parses an IPv6 CIDR block', () => {
		assert.match(
			equals([contains({ family: 6, addr: '2001:db8::', bits: 32 })]),
			fw4.parse_subnet('2001:db8::/32')
		);
	});

	it('returns null for an invalid address', () => {
		assert.match(equals(null), fw4.parse_subnet('not-an-ip'));
	});

	describe('— with networks in state', () => {
		beforeEach(() => {
			fw4.state = {
				networks: {
					lan: { ipaddrs: [{ family: 4, addr: '192.168.1.0', mask: '255.255.255.0', bits: 24 }] }
				}
			};
		});
		afterEach(() => { fw4.state = null; });

		it('resolves a network name to its configured addresses', () => {
			assert.match(
				equals([contains({ family: 4, addr: '192.168.1.0', bits: 24 })]),
				fw4.parse_subnet('lan')
			);
		});

		it('returns null for an unknown network name', () => {
			assert.match(equals(null), fw4.parse_subnet('unknown'));
		});
	});
});

describe('fw4.parse_mac', () => {
	it('parses a colon-separated MAC address', () => {
		assert.match(contains({ invert: false, mac: 'de:ad:be:ef:ca:fe' }), fw4.parse_mac('de:ad:be:ef:ca:fe'));
	});

	it('normalises uppercase to lowercase', () => {
		assert.match(contains({ mac: 'de:ad:be:ef:ca:fe' }), fw4.parse_mac('DE:AD:BE:EF:CA:FE'));
	});

	it('accepts dash-separated notation', () => {
		assert.match(contains({ mac: 'de:ad:be:ef:ca:fe' }), fw4.parse_mac('de-ad-be-ef-ca-fe'));
	});

	it('zero-pads single-digit octets', () => {
		assert.match(contains({ mac: '01:02:03:04:05:06' }), fw4.parse_mac('1:2:3:4:5:6'));
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true }), fw4.parse_mac('!de:ad:be:ef:ca:fe'));
	});

	it('returns null for a truncated MAC', () => {
		assert.match(equals(null), fw4.parse_mac('de:ad:be:ef:ca'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_mac(null));
	});
});

describe('fw4.parse_family', () => {
	it('returns 0 for any/all/*', () => {
		assert.match(equals(0), fw4.parse_family('any'));
		assert.match(equals(0), fw4.parse_family('all'));
		assert.match(equals(0), fw4.parse_family('*'));
	});

	it('returns 4 for inet and values containing "4"', () => {
		assert.match(equals(4), fw4.parse_family('inet'));
		assert.match(equals(4), fw4.parse_family('ipv4'));
		assert.match(equals(4), fw4.parse_family('4'));
	});

	it('returns 6 for values containing "6"', () => {
		assert.match(equals(6), fw4.parse_family('ipv6'));
		assert.match(equals(6), fw4.parse_family('6'));
	});

	it('returns null for unrecognised values', () => {
		assert.match(equals(null), fw4.parse_family('ethernet'));
	});
});

describe('fw4.parse_network', () => {
	it('wraps a subnet in a network object', () => {
		assert.match(
			contains({ invert: false, addrs: [contains({ family: 4 })] }),
			fw4.parse_network('192.168.1.0/24')
		);
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true }), fw4.parse_network('!10.0.0.1'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_network(null));
	});
});

describe('fw4.parse_device', () => {
	it('parses a device name', () => {
		assert.match(contains({ invert: false, device: 'eth0' }), fw4.parse_device('eth0'));
	});

	it('marks * as a wildcard', () => {
		assert.match(contains({ any: true }), fw4.parse_device('*'));
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true, device: 'eth0' }), fw4.parse_device('!eth0'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_device(null));
	});
});
