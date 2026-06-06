'use strict';

import { describe, it, assert, equals, contains, any_order } from 'utest';

const fw4 = require('fw4');

describe('fw4.parse_time', () => {
	it('parses an hour-only value', () => {
		assert.match(equals({ hour: 12, min: 0, sec: 0 }), fw4.parse_time('12'));
	});

	it('parses hours and minutes', () => {
		assert.match(equals({ hour: 12, min: 30, sec: 0 }), fw4.parse_time('12:30'));
	});

	it('parses hours, minutes and seconds', () => {
		assert.match(equals({ hour: 12, min: 30, sec: 45 }), fw4.parse_time('12:30:45'));
	});

	it('accepts the maximum valid time', () => {
		assert.match(equals({ hour: 23, min: 59, sec: 59 }), fw4.parse_time('23:59:59'));
	});

	it('returns null when hour exceeds 23', () => {
		assert.match(equals(null), fw4.parse_time('24:00:00'));
	});

	it('returns null when minutes exceed 59', () => {
		assert.match(equals(null), fw4.parse_time('12:60:00'));
	});

	it('returns null when seconds exceed 59', () => {
		assert.match(equals(null), fw4.parse_time('12:00:60'));
	});
});

describe('fw4.parse_date', () => {
	it('parses a year-only value, defaulting month and day to 1', () => {
		assert.match(equals({ year: 2024, month: 1, day: 1, hour: 0, min: 0, sec: 0 }), fw4.parse_date('2024'));
	});

	it('parses year and month', () => {
		assert.match(equals({ year: 2024, month: 6, day: 1, hour: 0, min: 0, sec: 0 }), fw4.parse_date('2024-06'));
	});

	it('parses a full date', () => {
		assert.match(equals({ year: 2024, month: 6, day: 15, hour: 0, min: 0, sec: 0 }), fw4.parse_date('2024-06-15'));
	});

	it('parses a date with an embedded time component', () => {
		assert.match(
			equals({ year: 2024, month: 6, day: 15, hour: 14, min: 30, sec: 0 }),
			fw4.parse_date('2024-06-15T14:30:00')
		);
	});

	it('returns null for a year before 1970', () => {
		assert.match(equals(null), fw4.parse_date('1969-01-01'));
	});

	it('returns null for a year after 2038', () => {
		assert.match(equals(null), fw4.parse_date('2039-01-01'));
	});

	it('returns null when month exceeds 12', () => {
		assert.match(equals(null), fw4.parse_date('2024-13-01'));
	});

	it('returns null when day exceeds 31', () => {
		assert.match(equals(null), fw4.parse_date('2024-01-32'));
	});
});

describe('fw4.parse_weekdays', () => {
	it('parses a single abbreviated day', () => {
		assert.match(contains({ invert: false, days: any_order(['Monday']) }), fw4.parse_weekdays('Mon'));
	});

	it('parses multiple space-separated days', () => {
		assert.match(contains({ days: any_order(['Monday', 'Friday']) }), fw4.parse_weekdays('Mon Fri'));
	});

	it('accepts full day names', () => {
		assert.match(contains({ days: any_order(['Wednesday']) }), fw4.parse_weekdays('Wednesday'));
	});

	it('deduplicates repeated days', () => {
		assert.match(contains({ days: any_order(['Monday']) }), fw4.parse_weekdays('Mon Mon'));
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true }), fw4.parse_weekdays('!Sat Sun'));
	});

	it('returns null for an unrecognised day name', () => {
		assert.match(equals(null), fw4.parse_weekdays('Moonday'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_weekdays(null));
	});
});

describe('fw4.parse_monthdays', () => {
	it('sets the corresponding array indices for each day number', () => {
		let result = fw4.parse_monthdays('1 15 31');
		assert.match(equals(true), result.days[1]);
		assert.match(equals(true), result.days[15]);
		assert.match(equals(true), result.days[31]);
	});

	it('handles the ! negation prefix', () => {
		assert.match(contains({ invert: true }), fw4.parse_monthdays('!10'));
	});

	it('returns null when a day number is below 1', () => {
		assert.match(equals(null), fw4.parse_monthdays('0'));
	});

	it('returns null when a day number exceeds 31', () => {
		assert.match(equals(null), fw4.parse_monthdays('32'));
	});

	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_monthdays(null));
	});
});
