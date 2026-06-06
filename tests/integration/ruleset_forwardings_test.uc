'use strict';

// Inter-zone forwarding behavior: family restrictions on forwarding rules.

import { describe, it, assert, contains, not, afterEach, mock } from 'utest';

// ── Global module setup ─────────────────────────────────────────────────────

const _h = require('test_harness');
const extractChain = _h.extractChain;

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

describe('forwardings — family selections', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('family: IPv6 forwarding only generates an IPv6 jump in the source zone forward chain', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wanA', device: ['eth0'], auto_helper: 0 },
				'@zone[1]': { '.type': 'zone', name: 'lan',  device: ['eth2'], auto_helper: 0 },
				'@forwarding[0]': { '.type': 'forwarding', src: 'lan', dest: 'wanA', family: 'IPv6' }
			},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'forward_lan');
		assert.match(contains('meta nfproto ipv6 jump accept_to_wanA'), chain);
		assert.match(not(contains('meta nfproto ipv4 jump accept_to_wanA')), chain);
	});

	it('family: IPv4 forwarding only generates an IPv4 jump in the source zone forward chain', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wanB', device: ['eth1'], auto_helper: 0 },
				'@zone[1]': { '.type': 'zone', name: 'lan',  device: ['eth2'], auto_helper: 0 },
				'@forwarding[0]': { '.type': 'forwarding', src: 'lan', dest: 'wanB', family: 'IPv4' }
			},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'forward_lan');
		assert.match(contains('meta nfproto ipv4 jump accept_to_wanB'), chain);
		assert.match(not(contains('meta nfproto ipv6 jump accept_to_wanB')), chain);
	});

	it('forwarding with no explicit family generates a dual-stack jump', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wan', device: ['eth0'], auto_helper: 0 },
				'@zone[1]': { '.type': 'zone', name: 'lan', device: ['eth1'], auto_helper: 0 },
				'@forwarding[0]': { '.type': 'forwarding', src: 'lan', dest: 'wan' }
			},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'forward_lan');
		assert.match(contains('jump accept_to_wan'),       chain);
		assert.match(not(contains('nfproto ipv4')),        chain);
		assert.match(not(contains('nfproto ipv6')),        chain);
	});
});
