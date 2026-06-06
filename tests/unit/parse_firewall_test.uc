'use strict';

import { describe, it, assert, equals, contains, beforeEach, afterEach } from 'utest';

const fw4 = require('fw4');

describe('fw4.parse_policy', () => {
	it('resolves accept, reject and drop', () => {
		assert.match(equals('accept'), fw4.parse_policy('accept'));
		assert.match(equals('reject'), fw4.parse_policy('reject'));
		assert.match(equals('drop'),   fw4.parse_policy('drop'));
	});

	it('matches by prefix', () => {
		assert.match(equals('accept'), fw4.parse_policy('acc'));
		assert.match(equals('drop'),   fw4.parse_policy('d'));
	});

	it('returns null for an unrecognised policy', () => {
		assert.match(equals(null), fw4.parse_policy('forward'));
		assert.match(equals(null), fw4.parse_policy(null));
	});
});

describe('fw4.parse_direction', () => {
	it('returns false for ingress direction', () => {
		assert.match(equals(false), fw4.parse_direction('in'));
		assert.match(equals(false), fw4.parse_direction('ingress'));
	});

	it('returns true for egress direction', () => {
		assert.match(equals(true), fw4.parse_direction('out'));
		assert.match(equals(true), fw4.parse_direction('egress'));
	});

	it('returns null for unrecognised values', () => {
		assert.match(equals(null), fw4.parse_direction('forward'));
		assert.match(equals(null), fw4.parse_direction(null));
	});
});

describe('fw4.parse_target', () => {
	it('resolves common targets', () => {
		assert.match(equals('accept'),     fw4.parse_target('accept'));
		assert.match(equals('drop'),       fw4.parse_target('drop'));
		assert.match(equals('reject'),     fw4.parse_target('reject'));
		assert.match(equals('notrack'),    fw4.parse_target('notrack'));
		assert.match(equals('dnat'),       fw4.parse_target('dnat'));
		assert.match(equals('masquerade'), fw4.parse_target('masquerade'));
	});

	it('is case-insensitive', () => {
		assert.match(equals('accept'), fw4.parse_target('ACCEPT'));
	});

	it('matches by prefix', () => {
		assert.match(equals('masquerade'), fw4.parse_target('masq'));
	});

	it('returns null for an unrecognised target', () => {
		assert.match(equals(null), fw4.parse_target('forward'));
		assert.match(equals(null), fw4.parse_target(null));
	});
});

describe('fw4.parse_reject_code', () => {
	it('resolves known reject codes', () => {
		assert.match(equals('tcp-reset'),        fw4.parse_reject_code('tcp-reset'));
		assert.match(equals('port-unreachable'), fw4.parse_reject_code('port-unreachable'));
		assert.match(equals('admin-prohibited'), fw4.parse_reject_code('admin-prohibited'));
		assert.match(equals('host-unreachable'), fw4.parse_reject_code('host-unreachable'));
		assert.match(equals('no-route'),         fw4.parse_reject_code('no-route'));
	});

	it('matches by prefix', () => {
		assert.match(equals('admin-prohibited'), fw4.parse_reject_code('admin'));
	});

	it('returns null for unrecognised codes', () => {
		assert.match(equals(null), fw4.parse_reject_code('invalid'));
		assert.match(equals(null), fw4.parse_reject_code(null));
	});
});

describe('fw4.parse_reflection_source', () => {
	it('resolves internal and external', () => {
		assert.match(equals('internal'), fw4.parse_reflection_source('internal'));
		assert.match(equals('external'), fw4.parse_reflection_source('external'));
	});

	it('matches by prefix', () => {
		assert.match(equals('internal'), fw4.parse_reflection_source('i'));
		assert.match(equals('external'), fw4.parse_reflection_source('e'));
	});

	it('returns null for unrecognised values', () => {
		assert.match(equals(null), fw4.parse_reflection_source('both'));
		assert.match(equals(null), fw4.parse_reflection_source(null));
	});
});

describe('fw4.parse_zone_ref', () => {
	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_zone_ref(null));
	});

	it('returns a wildcard reference for *', () => {
		assert.match(contains({ any: true }), fw4.parse_zone_ref('*'));
	});

	describe('— with configured zones', () => {
		beforeEach(() => { fw4.state = { zones: [{ name: 'lan' }, { name: 'wan' }] }; });
		afterEach(() => { fw4.state = null; });

		it('returns the matching zone wrapped in a reference object', () => {
			assert.match(
				contains({ any: false, zone: contains({ name: 'lan' }) }),
				fw4.parse_zone_ref('lan')
			);
		});

		it('returns null for an unknown zone name', () => {
			assert.match(equals(null), fw4.parse_zone_ref('dmz'));
		});
	});
});

describe('fw4.parse_cthelper', () => {
	it('returns null for null input', () => {
		assert.match(equals(null), fw4.parse_cthelper(null));
	});

	describe('— with configured helpers', () => {
		beforeEach(() => { fw4.state = { helpers: [{ name: 'ftp', proto: { name: 'tcp' } }] }; });
		afterEach(() => { fw4.state = null; });

		it('returns the matching helper merged with the invert wrapper', () => {
			assert.match(contains({ invert: false, name: 'ftp' }), fw4.parse_cthelper('ftp'));
		});

		it('returns null for an unknown helper name', () => {
			assert.match(equals(null), fw4.parse_cthelper('unknown'));
		});
	});
});
