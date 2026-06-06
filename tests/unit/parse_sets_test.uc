'use strict';

import { describe, it, assert, equals, contains } from 'utest';

const fw4 = require('fw4');

describe('fw4.parse_ipsettype', () => {
	it('defaults to src direction when none is specified', () => {
		assert.match(equals(['src', 'ip']),   fw4.parse_ipsettype('ip'));
		assert.match(equals(['src', 'port']), fw4.parse_ipsettype('port'));
		assert.match(equals(['src', 'mac']),  fw4.parse_ipsettype('mac'));
	});

	it('accepts an explicit src_ prefix', () => {
		assert.match(equals(['src', 'ip']), fw4.parse_ipsettype('src_ip'));
	});

	it('accepts dst_ and dest_ prefixes', () => {
		assert.match(equals(['dst', 'port']), fw4.parse_ipsettype('dst_port'));
		assert.match(equals(['dst', 'mac']),  fw4.parse_ipsettype('dest_mac'));
	});

	it('returns null for an unrecognised type', () => {
		assert.match(equals(null), fw4.parse_ipsettype('invalid'));
		assert.match(equals(null), fw4.parse_ipsettype('src_invalid'));
	});
});

describe('fw4.parse_setmatch', () => {
	it('parses a set name with no direction', () => {
		assert.match(contains({ invert: false, name: 'myset' }), fw4.parse_setmatch('myset'));
	});

	it('parses a set name with src and dst directions', () => {
		let result = fw4.parse_setmatch('myset src dst');
		assert.match(equals('myset'), result.name);
		assert.match(equals(['src', 'dst']), result.dir);
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true, name: 'myset' }), fw4.parse_setmatch('!myset'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_setmatch(null));
	});
});

describe('fw4.parse_includetype', () => {
	it('resolves script and nftables', () => {
		assert.match(equals('script'),   fw4.parse_includetype('script'));
		assert.match(equals('nftables'), fw4.parse_includetype('nftables'));
	});

	it('matches by prefix', () => {
		assert.match(equals('script'),   fw4.parse_includetype('s'));
		assert.match(equals('nftables'), fw4.parse_includetype('n'));
	});

	it('returns null for unrecognised values', () => {
		assert.match(equals(null), fw4.parse_includetype('other'));
		assert.match(equals(null), fw4.parse_includetype(null));
	});
});

describe('fw4.parse_includeposition', () => {
	it('resolves prepend and append positions for all scopes', () => {
		assert.match(equals('ruleset-prepend'), fw4.parse_includeposition('ruleset-prepend'));
		assert.match(equals('ruleset-append'),  fw4.parse_includeposition('ruleset-append'));
		assert.match(equals('table-prepend'),   fw4.parse_includeposition('table-prepend'));
		assert.match(equals('chain-append'),    fw4.parse_includeposition('chain-append'));
	});

	it('"postpend" is a deprecated alias that normalises to "append"', () => {
		assert.match(equals('ruleset-append'), fw4.parse_includeposition('ruleset-postpend'));
		assert.match(equals('table-append'),   fw4.parse_includeposition('table-postpend'));
		assert.match(equals('chain-append'),   fw4.parse_includeposition('chain-postpend'));
	});

	it('returns null for unrecognised positions', () => {
		assert.match(equals(null), fw4.parse_includeposition('invalid'));
		assert.match(equals(null), fw4.parse_includeposition(null));
	});
});
