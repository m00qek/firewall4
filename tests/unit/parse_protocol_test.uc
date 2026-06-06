'use strict';

import { describe, it, assert, equals, contains } from 'utest';

const fw4 = require('fw4');

describe('fw4.parse_protocol', () => {
	it('resolves tcp by name', () => {
		assert.match(contains({ invert: false, name: 'tcp' }), fw4.parse_protocol('tcp'));
	});

	it('resolves tcp by protocol number 6', () => {
		assert.match(contains({ name: 'tcp' }), fw4.parse_protocol('6'));
	});

	it('resolves udp by name', () => {
		assert.match(contains({ invert: false, name: 'udp' }), fw4.parse_protocol('udp'));
	});

	it('resolves udp by protocol number 17', () => {
		assert.match(contains({ name: 'udp' }), fw4.parse_protocol('17'));
	});

	it('expands tcpudp into two separate entries', () => {
		assert.match(
			equals([ contains({ name: 'tcp' }), contains({ name: 'udp' }) ]),
			fw4.parse_protocol('tcpudp')
		);
	});

	it('marks any/all/* as a wildcard', () => {
		assert.match(contains({ any: true }), fw4.parse_protocol('any'));
		assert.match(contains({ any: true }), fw4.parse_protocol('all'));
		assert.match(contains({ any: true }), fw4.parse_protocol('*'));
	});

	it('resolves icmp by name and by number 1', () => {
		assert.match(contains({ name: 'icmp' }), fw4.parse_protocol('icmp'));
		assert.match(contains({ name: 'icmp' }), fw4.parse_protocol('1'));
	});

	it('resolves icmpv6 by its three accepted names and by number 58', () => {
		const expected = contains({ name: 'ipv6-icmp' });
		assert.match(expected, fw4.parse_protocol('icmpv6'));
		assert.match(expected, fw4.parse_protocol('ipv6-icmp'));
		assert.match(expected, fw4.parse_protocol('58'));
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true, name: 'udp' }), fw4.parse_protocol('!udp'));
	});

	it('passes unknown protocol names through unchanged', () => {
		assert.match(contains({ name: 'esp' }), fw4.parse_protocol('esp'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_protocol(null));
	});
});
