'use strict';

import { describe, it, assert, equals } from 'utest';

const fw4 = require('fw4');

describe('fw4.parse_invert', () => {
	it('returns the value unchanged when no ! prefix', () => {
		assert.match(equals({ invert: false, val: '80' }), fw4.parse_invert('80'));
	});

	it('strips ! and sets invert flag', () => {
		assert.match(equals({ invert: true, val: '80' }), fw4.parse_invert('!80'));
	});

	it('tolerates whitespace between ! and value', () => {
		assert.match(equals({ invert: true, val: '80' }), fw4.parse_invert('! 80'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_invert(null));
	});

	it('returns null when only whitespace remains after stripping !', () => {
		assert.match(equals(null), fw4.parse_invert('!'));
	});
});

describe('fw4.parse_bool', () => {
	it('accepts "1", "on", "true" and "yes" as true', () => {
		assert.match(equals(true), fw4.parse_bool('1'));
		assert.match(equals(true), fw4.parse_bool('on'));
		assert.match(equals(true), fw4.parse_bool('true'));
		assert.match(equals(true), fw4.parse_bool('yes'));
	});

	it('accepts "0", "off", "false" and "no" as false', () => {
		assert.match(equals(false), fw4.parse_bool('0'));
		assert.match(equals(false), fw4.parse_bool('off'));
		assert.match(equals(false), fw4.parse_bool('false'));
		assert.match(equals(false), fw4.parse_bool('no'));
	});

	it('returns null for unrecognised values', () => {
		assert.match(equals(null), fw4.parse_bool('maybe'));
		assert.match(equals(null), fw4.parse_bool(null));
	});
});

describe('fw4.parse_int', () => {
	it('converts a decimal string to a number', () => {
		assert.match(equals(42), fw4.parse_int('42'));
	});

	it('converts zero', () => {
		assert.match(equals(0), fw4.parse_int('0'));
	});

	it('passes through a number directly', () => {
		assert.match(equals(7), fw4.parse_int(7));
	});

	it('returns null for non-numeric strings', () => {
		assert.match(equals(null), fw4.parse_int('abc'));
	});
});

describe('fw4.parse_enum', () => {
	const choices = ['accept', 'reject', 'drop'];

	it('matches an exact value', () => {
		assert.match(equals('accept'), fw4.parse_enum('accept', choices));
	});

	it('matches by case-insensitive prefix', () => {
		assert.match(equals('accept'), fw4.parse_enum('Acc', choices));
		assert.match(equals('reject'), fw4.parse_enum('rej', choices));
	});

	it('returns the first match when prefixes are ambiguous', () => {
		assert.match(equals('accept'), fw4.parse_enum('a', ['accept', 'admin']));
	});

	it('returns null when no choice matches', () => {
		assert.match(equals(null), fw4.parse_enum('forward', choices));
	});

	it('returns null for non-string input', () => {
		assert.match(equals(null), fw4.parse_enum(null, choices));
	});
});

describe('fw4.parse_identifier', () => {
	it('accepts letters, digits, underscores, dots and dashes', () => {
		assert.match(equals('my_chain.0-a'), fw4.parse_identifier('my_chain.0-a'));
	});

	it('accepts identifiers starting with an underscore', () => {
		assert.match(equals('_private'), fw4.parse_identifier('_private'));
	});

	it('returns null when the identifier starts with a digit', () => {
		assert.match(equals(null), fw4.parse_identifier('123chain'));
	});

	it('returns null when the identifier contains spaces', () => {
		assert.match(equals(null), fw4.parse_identifier('my chain'));
	});

	it('returns null for an empty string', () => {
		assert.match(equals(null), fw4.parse_identifier(''));
	});
});

describe('fw4.parse_string', () => {
	it('returns the string unchanged', () => {
		assert.match(equals('hello'), fw4.parse_string('hello'));
	});

	it('converts numbers to strings', () => {
		assert.match(equals('42'), fw4.parse_string(42));
	});
});
