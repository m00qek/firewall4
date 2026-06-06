'use strict';

// IPset declaration and usage in rules.

import { describe, it, assert, truthy, contains, not, afterEach, mock } from 'utest';

// ── Global module setup ─────────────────────────────────────────────────────

const _h = require('test_harness');
const extractChain = _h.extractChain;

function extractSet(ruleset, name) {
	let lines = split(ruleset, '\n');
	let result = [], inSet = false;
	for (let line in lines) {
		if (!inSet) {
			if (line == `\tset ${name} {`) inSet = true;
		} else {
			if (line == '\t}') break;
			push(result, line);
		}
	}
	return inSet ? join('\n', result) : null;
}

const KERNEL   = 'Linux version 5.4.101 (build) #0 SMP Tue Mar 2 14:41:54 2021\n';
const NFT_JSON = '{"nftables":[{"metainfo":{"json_schema_version":1}}]}';
const BASE_FILES    = { '/proc/version': KERNEL, '/sys/class/net/eth0/flags': '0x1003', '/sys/class/net/eth1/flags': '0x1003' };
const BASE_COMMANDS = { '/usr/sbin/nft --terse --json list flowtables inet': NFT_JSON };

function fs_patch(extra_data) {
	const data = { ...BASE_FILES, ...(extra_data ?? {}) };
	return {
		strict:   true,
		behavior: {
			readfile: function(path) {
				if (exists(data, path)) return data[path];
				if (match(path, /^\/sys\/class\/net\/.+\/flags$/)) return '0x1003';
				die("strict mock: 'fs.readfile' called with unmocked path: " + path);
			}
		},
		data,
		commands: BASE_COMMANDS
	};
}

mock.global.patch('uci',  {});
mock.global.patch('fs',   fs_patch());
mock.global.patch('ubus', {});

const fw4 = require('fw4');
const renderWith = _h.makeRenderWith(fw4);

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('ipsets — declaration', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.patch('fs', fs_patch()); });

	it('set type is derived from match options and family', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@ipset[0]': { '.type': 'ipset', name: 'test-set', family: 'IPv4',
				               match: ['src_ip', 'dest_port'] }
			},
			helpers: {}
		}});
		assert.match(contains('type ipv4_addr . inet_service'), extractSet(renderWith(), 'test-set'));
	});

	it('comment option is rendered inside the set block', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@ipset[0]': { '.type': 'ipset', name: 'test-set', family: 'IPv4',
				               match: ['src_ip', 'dest_port'], comment: 'A simple set' }
			},
			helpers: {}
		}});
		assert.match(contains('comment "A simple set"'), extractSet(renderWith(), 'test-set'));
	});

	it('counters: 1 is accepted and the set renders without error (option is currently a no-op)', () => {
		// fw4 parses counters as a valid UCI bool but does not yet emit a counter
		// flag into the nftables set declaration.  This test documents the current
		// behaviour so a future implementation change is immediately visible.
		mock.global.patch('uci', { data: {
			firewall: {
				'@ipset[0]': { '.type': 'ipset', name: 'test-set', family: 'IPv4',
				               match: ['src_ip'], counters: '1' }
			},
			helpers: {}
		}});
		const set = extractSet(renderWith(), 'test-set');
		assert.match(truthy(), set !== null);
		assert.match(contains('type ipv4_addr'), set);
	});

	it('timeout and maxelem options are rendered', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@ipset[0]': { '.type': 'ipset', name: 'test-set', family: 'IPv4',
				               match: ['src_ip', 'dest_port'], timeout: '600', maxelem: '1000' }
			},
			helpers: {}
		}});
		const set = extractSet(renderWith(), 'test-set');
		assert.match(contains('timeout 600s'),  set);
		assert.match(contains('flags timeout'), set);
		assert.match(contains('size 1000'),     set);
	});

	it('inline entries are rendered in the elements block', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@ipset[0]': { '.type': 'ipset', name: 'test-set', family: 'IPv4',
				               match: ['src_ip', 'dest_port'],
				               entry: ['1.2.3.4 80', '5.6.7.8 22'] }
			},
			helpers: {}
		}});
		const set = extractSet(renderWith(), 'test-set');
		assert.match(contains('1.2.3.4 . 80'), set);
		assert.match(contains('5.6.7.8 . 22'), set);
	});

	it('loadfile entries are merged with inline entries', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@ipset[0]': { '.type': 'ipset', name: 'test-set', family: 'IPv4',
				               match: ['src_ip', 'dest_port'],
				               entry: ['1.2.3.4 80'],
				               loadfile: 'set-entries.txt' }
			},
			helpers: {}
		}});
		mock.global.patch('fs', fs_patch({ 'set-entries.txt': '10.11.12.13 53\n172.16.27.1 443\n' }));
		const set = extractSet(renderWith(), 'test-set');
		assert.match(contains('1.2.3.4 . 80'),       set);
		assert.match(contains('10.11.12.13 . 53'),   set);
		assert.match(contains('172.16.27.1 . 443'),  set);
	});
});

describe('ipsets — usage in rules', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.patch('fs', fs_patch()); });

	// test-set-1: src_ip + dest_port (direction encoded in names)
	// test-set-2: ip + port (direction unspecified, defaults to source)
	const SETS = {
		'@ipset[0]': { '.type': 'ipset', name: 'test-set-1',
		               match: ['src_ip', 'dest_port'], entry: ['1.2.3.4 80'] },
		'@ipset[1]': { '.type': 'ipset', name: 'test-set-2',
		               match: ['ip', 'port'], entry: ['1.2.3.4 80'] }
	};

	it('default match direction is source', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				...SETS,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: '*', proto: 'tcp', ipset: 'test-set-2' }
			},
			helpers: {}
		}});
		assert.match(contains('ip saddr . tcp sport @test-set-2'), extractChain(renderWith(), 'forward'));
	});

	it('traffic direction in match option names takes precedence', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				...SETS,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: '*', proto: 'tcp', ipset: 'test-set-1' }
			},
			helpers: {}
		}});
		assert.match(contains('ip saddr . tcp dport @test-set-1'), extractChain(renderWith(), 'forward'));
	});

	it('explicit dst src direction overrides the set type direction', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				...SETS,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: '*', proto: 'tcp', ipset: 'test-set-1 dst src' }
			},
			helpers: {}
		}});
		assert.match(contains('ip daddr . tcp sport @test-set-1'), extractChain(renderWith(), 'forward'));
	});

	it('explicit dst dst direction matches destination address and destination port', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				...SETS,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: '*', proto: 'tcp', ipset: 'test-set-2 dst dst' }
			},
			helpers: {}
		}});
		assert.match(contains('ip daddr . tcp dport @test-set-2'), extractChain(renderWith(), 'forward'));
	});

	it('inverted match uses != operator', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				...SETS,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: '*', proto: 'tcp', ipset: '!test-set-1 dst src' }
			},
			helpers: {}
		}});
		assert.match(contains('ip daddr . tcp sport != @test-set-1'), extractChain(renderWith(), 'forward'));
	});

	it('IPv6 set inherits IPv6 family for the rule', () => {
		// net match type requires kernel >= 5.6; patch fs to report a 5.10 kernel.
		mock.global.patch('fs', fs_patch({ '/proc/version': 'Linux version 5.10.0 (build) #0 SMP\n' }));
		const SET3 = { '.type': 'ipset', name: 'test-set-3', family: 'IPv6',
		               match: ['net', 'net', 'port'], entry: ['db80:1234::/64 db80:abcd::/64 80'] };
		mock.global.patch('uci', { data: {
			firewall: {
				...SETS,
				'@ipset[2]': SET3,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: '*', proto: 'tcp', ipset: 'test-set-3 src,dest,dest' }
			},
			helpers: {}
		}});
		assert.match(contains('ip6 saddr . ip6 daddr . tcp dport @test-set-3'),
			extractChain(renderWith(), 'forward'));
	});
});
