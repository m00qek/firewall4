'use strict';

import { describe, it, assert, equals, contains } from 'utest';

const fw4 = require('fw4');

describe('fw4.parse_icmptype', () => {
	it('resolves a pure ICMPv4 type by name', () => {
		// source-quench is IPv4 only (type 4)
		assert.match(contains({ family: 4, type: 4 }), fw4.parse_icmptype('source-quench'));
	});

	it('resolves a pure ICMPv6 type by name', () => {
		// packet-too-big is IPv6 only (type 2)
		assert.match(contains({ family: 6, type6: 2 }), fw4.parse_icmptype('packet-too-big'));
	});

	it('resolves a type present in both ICMP tables', () => {
		// echo-request: IPv4 type 8, IPv6 type 128 — family becomes 0 (both)
		assert.match(
			contains({ family: 0, type: 8, type6: 128 }),
			fw4.parse_icmptype('echo-request')
		);
	});

	it('resolves a type that maps to different numbers in ICMPv4 and ICMPv6', () => {
		// router-solicitation: IPv4 type 10, IPv6 type 133
		assert.match(
			contains({ family: 0, type: 10, type6: 133 }),
			fw4.parse_icmptype('router-solicitation')
		);
	});

	it('accepts an alias — ping and echo-request resolve identically', () => {
		assert.match(equals(fw4.parse_icmptype('echo-request')), fw4.parse_icmptype('ping'));
	});

	it('parses a bare numeric type — applies to both address families', () => {
		assert.match(
			contains({ family: 0, type: 8, type6: 8, code_min: 0, code_max: 0xFF }),
			fw4.parse_icmptype('8')
		);
	});

	it('parses a numeric type with an explicit code', () => {
		assert.match(
			contains({ type: 8, code_min: 3, code_max: 3 }),
			fw4.parse_icmptype('8/3')
		);
	});

	it('returns null for a type number above 255', () => {
		assert.match(equals(null), fw4.parse_icmptype('256'));
	});

	it('returns null for an unrecognised name', () => {
		assert.match(equals(null), fw4.parse_icmptype('invalid-type'));
	});
});

// Regression: commit 30ee17a ("fw4: fix syntax errors in ICMP type declarations")
// Five entries in ipv6_icmptypes were missing their colon separator, causing a
// compile-time syntax error that prevented fw4.uc from loading at all.
describe('fw4.parse_icmptype — ICMPv6 entries that were missing colon separators now resolve', () => {
	it('"extended-echo-request" resolves to ICMPv6 type 160', () => {
		assert.match(contains({ family: 6, type6: 160 }), fw4.parse_icmptype('extended-echo-request'));
	});

	it('"extended-ping" resolves identically to "extended-echo-request"', () => {
		assert.match(
			equals(fw4.parse_icmptype('extended-echo-request')),
			fw4.parse_icmptype('extended-ping')
		);
	});

	it('"extended-echo-reply" resolves to ICMPv6 type 161', () => {
		assert.match(contains({ family: 6, type6: 161 }), fw4.parse_icmptype('extended-echo-reply'));
	});

	it('"extended-pong" resolves identically to "extended-echo-reply"', () => {
		assert.match(
			equals(fw4.parse_icmptype('extended-echo-reply')),
			fw4.parse_icmptype('extended-pong')
		);
	});

	it('"duplicate-address-confirmation" resolves to ICMPv6 type 158', () => {
		assert.match(contains({ family: 6, type6: 158 }), fw4.parse_icmptype('duplicate-address-confirmation'));
	});
});
