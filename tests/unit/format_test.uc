'use strict';

import { describe, it, assert, equals } from 'utest';

const fw4 = require('fw4');

describe('fw4.cidr', () => {
	it('returns just the address for a host route', () => {
		assert.match(equals('1.2.3.4'), fw4.cidr({ family: 4, addr: '1.2.3.4', bits: 32 }));
		assert.match(equals('::1'),     fw4.cidr({ family: 6, addr: '::1',     bits: 128 }));
	});

	it('returns address/prefix for a network', () => {
		assert.match(equals('10.0.0.0/8'),    fw4.cidr({ family: 4, addr: '10.1.2.3',  bits: 8 }));
		assert.match(equals('2001:db8::/32'), fw4.cidr({ family: 6, addr: '2001:db8::', bits: 32 }));
	});

	it('returns address/mask for a non-contiguous mask', () => {
		assert.match(
			equals('0.0.0.0/255.0.255.0'),
			fw4.cidr({ family: 4, addr: '0.0.0.0', bits: -1, mask: '255.0.255.0' })
		);
	});

	it('returns addr-addr2 for a range', () => {
		assert.match(
			equals('192.168.1.1-192.168.1.10'),
			fw4.cidr({ addr: '192.168.1.1', addr2: '192.168.1.10', range: true })
		);
	});
});

describe('fw4.host', () => {
	it('returns the masked address for an IPv4 network', () => {
		assert.match(equals('192.168.1.0'), fw4.host({ family: 4, addr: '192.168.1.0', bits: 24 }));
	});

	it('returns addr-addr2 for a range', () => {
		assert.match(equals('1.2.3.4-1.2.3.10'), fw4.host({ addr: '1.2.3.4', addr2: '1.2.3.10', range: true }));
	});

	it('wraps IPv6 addresses in brackets when requested', () => {
		assert.match(equals('[::1]'), fw4.host({ family: 6, addr: '::1', bits: 128 }, true));
	});

	it('does not wrap IPv6 addresses without the bracket flag', () => {
		assert.match(equals('::1'), fw4.host({ family: 6, addr: '::1', bits: 128 }, false));
	});
});

describe('fw4.port', () => {
	it('returns a single number for a single port', () => {
		assert.match(equals('80'), fw4.port({ min: 80, max: 80 }));
	});

	it('returns a range notation for a port range', () => {
		assert.match(equals('1024-65535'), fw4.port({ min: 1024, max: 65535 }));
	});
});

describe('fw4.quote', () => {
	it('does not quote values made of safe characters', () => {
		assert.match(equals('10.0.0.1'),    fw4.quote('10.0.0.1'));
		assert.match(equals('aa:bb:cc:dd'), fw4.quote('aa:bb:cc:dd'));
	});

	it('quotes values containing characters outside the safe set', () => {
		assert.match(equals('"my_chain"'), fw4.quote('my_chain'));
		assert.match(equals('"hello world"'), fw4.quote('hello world'));
	});

	it('replaces embedded double quotes with single quotes', () => {
		assert.match(equals(`"say 'hi'"`), fw4.quote('say "hi"'));
	});

	it('quotes unconditionally when force is true', () => {
		assert.match(equals('"10.0.0.1"'), fw4.quote('10.0.0.1', true));
	});
});

describe('fw4.set', () => {
	it('returns the bare value for a single element', () => {
		assert.match(equals('80'), fw4.set('80'));
	});

	it('returns a brace-enclosed list for multiple elements', () => {
		assert.match(equals('{ 80, 443 }'), fw4.set(['80', '443']));
	});

	it('deduplicates repeated values', () => {
		assert.match(equals('80'), fw4.set(['80', '80']));
	});

	it('forces braces even for a single element when requested', () => {
		assert.match(equals('{ 80 }'), fw4.set('80', true));
	});

	it('quotes single elements that contain unsafe characters', () => {
		assert.match(equals('"my chain"'), fw4.set(['my chain']));
	});
});

describe('fw4.concat', () => {
	it('returns a single value unchanged', () => {
		assert.match(equals('a'), fw4.concat('a'));
	});

	it('joins multiple values with " . "', () => {
		assert.match(equals('ip saddr . ip daddr'), fw4.concat(['ip saddr', 'ip daddr']));
	});
});

describe('fw4.ipproto', () => {
	it('returns ip for IPv4', () => {
		assert.match(equals('ip'), fw4.ipproto(4));
	});

	it('returns ip6 for IPv6', () => {
		assert.match(equals('ip6'), fw4.ipproto(6));
	});
});

describe('fw4.nfproto', () => {
	it('returns nftables family keywords', () => {
		assert.match(equals('ipv4'), fw4.nfproto(4));
		assert.match(equals('ipv6'), fw4.nfproto(6));
		assert.match(equals(null),   fw4.nfproto(0));
	});

	it('returns human-readable labels when requested', () => {
		assert.match(equals('IPv4'),     fw4.nfproto(4, true));
		assert.match(equals('IPv6'),     fw4.nfproto(6, true));
		assert.match(equals('IPv4/IPv6'), fw4.nfproto(0, true));
	});
});

describe('fw4.datetime / fw4.date / fw4.datestamp', () => {
	const full  = { year: 2024, month: 6, day: 15, hour: 14, min: 30, sec: 0 };
	const notime = { year: 2024, month: 6, day: 15 };

	it('datetime formats all fields as a quoted string', () => {
		assert.match(equals('"2024-06-15 14:30:00"'), fw4.datetime(full));
	});

	it('date formats only the date part as a quoted string', () => {
		assert.match(equals('"2024-06-15"'), fw4.date(notime));
	});

	it('datestamp delegates to datetime when hour is present', () => {
		assert.match(equals(fw4.datetime(full)), fw4.datestamp(full));
	});

	it('datestamp delegates to date when no hour is present', () => {
		assert.match(equals(fw4.date(notime)), fw4.datestamp(notime));
	});
});

// Regression: commit 4c01d1e ("fw4: substitute double quotes in strings")
// The old code tried to backslash-escape embedded double quotes, producing \"
// inside an outer double-quoted string. nftables has no escape syntax, so the
// generated ruleset caused a parse error. The fix replaces " with ' instead.
describe('fw4.quote — embedded double quotes become single quotes', () => {
	it('replaces " with \' so the output remains valid nftables syntax', () => {
		// Old code produced: "say \"hi\"" — invalid in nft (no escape sequences in strings)
		// New code produces: "say 'hi'"  — valid nftables quoted string
		assert.match(equals(`"say 'hi'"`), fw4.quote('say "hi"'));
	});

	it('handles a string consisting entirely of double quotes', () => {
		assert.match(equals(`"''"`), fw4.quote('""'));
	});
});
