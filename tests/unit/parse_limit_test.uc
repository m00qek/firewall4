'use strict';

import { describe, it, assert, equals, contains } from 'utest';

const fw4 = require('fw4');

describe('fw4.parse_limit', () => {
	it('parses rate with explicit unit', () => {
		assert.match(contains({ invert: false, rate: 25, unit: 'second' }), fw4.parse_limit('25/second'));
	});

	it('defaults to seconds when no unit is specified', () => {
		assert.match(contains({ rate: 10, unit: 'second' }), fw4.parse_limit('10'));
	});

	it('accepts abbreviated unit names via prefix matching', () => {
		assert.match(contains({ unit: 'minute' }), fw4.parse_limit('100/min'));
		assert.match(contains({ unit: 'hour' }),   fw4.parse_limit('5/h'));
		assert.match(contains({ unit: 'day' }),    fw4.parse_limit('1/d'));
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true, rate: 5, unit: 'hour' }), fw4.parse_limit('!5/hour'));
	});

	it('returns null for an unrecognised unit', () => {
		assert.match(equals(null), fw4.parse_limit('10/century'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_limit(null));
	});
});

describe('fw4.parse_mark', () => {
	it('parses a hex mark with an implicit full mask', () => {
		assert.match(contains({ invert: false, mark: 0x1000, mask: 0xFFFFFFFF }), fw4.parse_mark('0x1000'));
	});

	it('parses a decimal mark', () => {
		assert.match(contains({ mark: 42 }), fw4.parse_mark('42'));
	});

	it('parses a mark/mask pair', () => {
		assert.match(contains({ mark: 0xFF, mask: 0x0F }), fw4.parse_mark('0xff/0x0f'));
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true }), fw4.parse_mark('!0x10'));
	});

	it('accepts the maximum 32-bit mark value', () => {
		assert.match(contains({ mark: 0xFFFFFFFF }), fw4.parse_mark('0xffffffff'));
	});

	it('returns null for a value exceeding 32 bits', () => {
		assert.match(equals(null), fw4.parse_mark('0x100000000'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_mark(null));
	});
});

describe('fw4.parse_dscp', () => {
	it('resolves named DSCP classes', () => {
		assert.match(contains({ dscp: 0x2e }), fw4.parse_dscp('EF'));
		assert.match(contains({ dscp: 0x0a }), fw4.parse_dscp('AF11'));
		assert.match(contains({ dscp: 0x00 }), fw4.parse_dscp('CS0'));
	});

	it('is case-insensitive for class names', () => {
		assert.match(contains({ dscp: 0x2e }), fw4.parse_dscp('ef'));
		assert.match(contains({ dscp: 0x0a }), fw4.parse_dscp('af11'));
	});

	it('parses a numeric DSCP value', () => {
		assert.match(contains({ dscp: 63 }), fw4.parse_dscp('63'));
	});

	it('returns null for a numeric value above 63', () => {
		assert.match(equals(null), fw4.parse_dscp('64'));
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true }), fw4.parse_dscp('!EF'));
	});

	it('returns null for an unrecognised class name', () => {
		assert.match(equals(null), fw4.parse_dscp('INVALID'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_dscp(null));
	});
});
