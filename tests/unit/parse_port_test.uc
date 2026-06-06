'use strict';

import { describe, it, assert, equals, contains } from 'utest';

const fw4 = require('fw4');

describe('fw4.parse_port', () => {
	it('parses a single port', () => {
		assert.match(contains({ invert: false, min: 80, max: 80 }), fw4.parse_port('80'));
	});

	it('accepts port zero', () => {
		assert.match(contains({ min: 0, max: 0 }), fw4.parse_port('0'));
	});

	it('parses a range separated by colon', () => {
		assert.match(contains({ min: 1024, max: 65535 }), fw4.parse_port('1024:65535'));
	});

	it('parses a range separated by dash', () => {
		assert.match(contains({ min: 1024, max: 65535 }), fw4.parse_port('1024-65535'));
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true, min: 22, max: 22 }), fw4.parse_port('!22'));
	});

	it('handles negation with surrounding whitespace', () => {
		assert.match(contains({ invert: true, min: 22, max: 22 }), fw4.parse_port('! 22'));
	});

	it('returns null for port above 65535', () => {
		assert.match(equals(null), fw4.parse_port('65536'));
	});

	it('returns null when range min exceeds max', () => {
		assert.match(equals(null), fw4.parse_port('8080:80'));
	});

	it('returns null for a named service', () => {
		assert.match(equals(null), fw4.parse_port('ssh'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_port(null));
	});
});
