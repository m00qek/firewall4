'use strict';

// Redirect, DNAT, and reflection (srcnat) rule rendering.

import { describe, it, assert, truthy, contains, not, afterEach, mock } from 'utest';

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

describe('rules — redirect', () => {
	afterEach(() => mock.global.unpatch('uci'));

	const ZONES = {
		'@zone[0]': { '.type': 'zone', name: 'wan', device: 'eth0', masq: '1' },
		'@zone[1]': { '.type': 'zone', name: 'lan', device: 'eth1', auto_helper: 0 }
	};

	it('dnat without dest_ip redirects to the same port on the router', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@redirect[0]': { '.type': 'redirect', name: 'r', src: 'wan',
				                  proto: 'udp', src_dport: '53', dest_port: '53', target: 'dnat' }
			},
			helpers: {}
		}});
		assert.match(contains('udp dport 53 counter redirect to 53'), extractChain(renderWith(), 'dstnat_wan'));
	});

	it('dnat with dest_ip generates a DNAT rule to the target address', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@redirect[0]': { '.type': 'redirect', name: 'r', src: 'wan',
				                  proto: 'tcp', src_dport: '22', dest_ip: '192.168.1.100' }
			},
			helpers: {}
		}});
		assert.match(contains('dnat 192.168.1.100:22'), extractChain(renderWith(), 'dstnat_wan'));
	});

	it('IPv6 dnat address uses bracket notation', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@redirect[0]': { '.type': 'redirect', name: 'r', family: 'ipv6', src: 'wan', dest: 'lan',
				                  proto: 'tcp', src_dport: '25', dest_ip: '2001:db8::1', dest_port: '25', target: 'dnat' }
			},
			helpers: {}
		}});
		assert.match(contains('dnat [2001:db8::1]:25'), extractChain(renderWith(), 'dstnat_wan'));
	});

	it('family: any redirect generates rules for both IPv4 and IPv6', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@redirect[0]': { '.type': 'redirect', name: 'r', family: 'any', src: 'wan',
				                  proto: 'udp', src_dport: '53', dest_port: '53', target: 'dnat' }
			},
			helpers: {}
		}});
		// family: any with no address → IPv4/IPv6 redirect (no nfproto qualifier)
		const dstnat_wan = extractChain(renderWith(), 'dstnat_wan');
		assert.match(truthy(), dstnat_wan !== null);
		assert.match(contains('udp dport 53 counter redirect to 53'), dstnat_wan);
		assert.match(not(contains('nfproto')), dstnat_wan);
	});

	it('family: ipv4 redirect generates only an IPv4 rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@redirect[0]': { '.type': 'redirect', name: 'r', family: 'ipv4', src: 'wan', dest: 'lan',
				                  proto: 'tcp', src_dport: '26', dest_port: '26', target: 'dnat' }
			},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'dstnat_wan');
		assert.match(contains('nfproto ipv4'),      chain);
		assert.match(not(contains('nfproto ipv6')), chain);
	});
});

describe('rules — redirect log limiting', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.unpatch('ubus'); });

	const IFACES = { interface: [
		{ interface: 'wan', up: true, l3_device: 'pppoe-wan', device: 'pppoe-wan',
		  'ipv4-address': [{ address: '10.11.12.194', mask: 24 }] }
	] };

	it('zone log_limit applies a named rate-limit log to redirect dstnat rules', () => {
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wan', network: ['wan'], masq: '1',
				              auto_helper: 0, log: '1', log_limit: '4/min' },
				'@redirect[0]': { '.type': 'redirect', name: 'r', src: 'wan', proto: 'tcp',
				                  dest_ip: '10.0.0.2', dest_port: '22', log: '1' }
			},
			helpers: {}
		}});
		const dstnat_wan = extractChain(renderWith(), 'dstnat_wan');
		assert.match(truthy(), dstnat_wan !== null);
		assert.match(contains('limit name "wan.log_limit"'), dstnat_wan);
		assert.match(contains('dnat 10.0.0.2:22'),           dstnat_wan);
	});

	it('per-redirect log_limit overrides the zone limit with an inline rate', () => {
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wan', network: ['wan'], masq: '1',
				              auto_helper: 0, log: '1', log_limit: '4/min' },
				'@redirect[0]': { '.type': 'redirect', name: 'r', src: 'wan', proto: 'tcp',
				                  dest_ip: '10.0.0.2', dest_port: '23', log: '1', log_limit: '10/sec' }
			},
			helpers: {}
		}});
		const dstnat_wan = extractChain(renderWith(), 'dstnat_wan');
		assert.match(truthy(), dstnat_wan !== null);
		assert.match(contains('limit rate 10/second'), dstnat_wan);
		assert.match(not(contains('limit name "wan.log_limit"')), dstnat_wan);
	});
});

describe('rules — redirect reflection', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.unpatch('ubus'); });

	const IFACES = { interface: [
		{ interface: 'lan',  up: true, l3_device: 'br-lan',   device: 'br-lan',
		  'ipv4-address': [{ address: '10.0.0.1', mask: 24 }, { address: '192.168.26.1', mask: 24 }] },
		{ interface: 'wan',  up: true, l3_device: 'pppoe-wan', device: 'pppoe-wan',
		  'ipv4-address': [{ address: '10.11.12.194', mask: 24 }] },
		{ interface: 'noaddr', up: true, l3_device: 'wwan0', device: 'wwan0' }
	] };

	const NET_ZONES = {
		'@zone[0]': { '.type': 'zone', name: 'wan', network: ['wan'], masq: '1', auto_helper: 0 },
		'@zone[1]': { '.type': 'zone', name: 'lan', network: ['lan'], auto_helper: 0 }
	};

	it('dnat without dest zone infers the destination zone from the dest_ip address', () => {
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		mock.global.patch('uci', { data: {
			firewall: {
				...NET_ZONES,
				'@redirect[0]': { '.type': 'redirect', name: 'r', src: 'wan', proto: 'tcp',
				                  src_dport: '22', dest_ip: '192.168.26.100' }
			},
			helpers: {}
		}});
		const nft = renderWith();
		// Main dnat rule lands in the wan dstnat chain
		assert.match(contains('dnat 192.168.26.100:22'), extractChain(nft, 'dstnat_wan'));
		// Reflection rules are generated (dest zone inferred from dest_ip = 192.168.26.100 → lan subnet)
		assert.match(contains('snat 192.168.26.1'), extractChain(nft, 'srcnat_lan'));
	});

	it('reflection_src: external uses the src zone address as the SNAT source', () => {
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		mock.global.patch('uci', { data: {
			firewall: {
				...NET_ZONES,
				'@redirect[0]': { '.type': 'redirect', name: 'r', src: 'wan', proto: 'tcp',
				                  src_dport: '23', dest_ip: '192.168.26.100',
				                  reflection_src: 'external' }
			},
			helpers: {}
		}});
		// External reflection uses the WAN address (10.11.12.194) as SNAT source
		assert.match(contains('snat 10.11.12.194'), extractChain(renderWith(), 'srcnat_lan'));
	});

	it('reflection is skipped when the src zone has no address', () => {
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		mock.global.patch('uci', { data: {
			firewall: {
				...NET_ZONES,
				'@zone[2]': { '.type': 'zone', name: 'noaddr', network: ['noaddr'], auto_helper: 0 },
				'@redirect[0]': { '.type': 'redirect', name: 'r', src: 'noaddr', dest: 'lan', proto: 'tcp',
				                  src_dport: '24', dest_ip: '192.168.26.100' }
			},
			helpers: {}
		}});
		const nft = renderWith();
		// Main dnat rule still appears
		assert.match(contains('dnat 192.168.26.100:24'), extractChain(nft, 'dstnat_noaddr'));
		// But no reflection rules in srcnat_lan
		assert.match(not(contains('reflection')), extractChain(nft, 'srcnat_lan') ?? '');
	});

	it('reflection_zone list generates reflection rules in each named zone srcnat chain', () => {
		const ifaces_with_guest = { interface: [
			...IFACES.interface,
			{ interface: 'guest', up: true, l3_device: 'br-guest', device: 'br-guest',
			  'ipv4-address': [{ address: '10.1.0.1', mask: 24 }] }
		] };
		mock.global.patch('ubus', { data: { 'network.interface:dump': ifaces_with_guest } });
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wan',   network: ['wan'],   masq: '1',   auto_helper: 0 },
				'@zone[1]': { '.type': 'zone', name: 'lan',   network: ['lan'],   auto_helper: 0 },
				'@zone[2]': { '.type': 'zone', name: 'guest', network: ['guest'], auto_helper: 0 },
				'@redirect[0]': { '.type': 'redirect', name: 'r', src: 'wan', proto: 'tcp',
				                  src_dport: '22', dest_ip: '10.0.0.2',
				                  reflection_zone: ['lan', 'guest'] }
			},
			helpers: {}
		}});
		const nft = renderWith();
		// DNAT rule appears in dstnat_wan
		assert.match(contains('dnat 10.0.0.2:22'), extractChain(nft, 'dstnat_wan'));
		// Hairpin SNAT rules are generated in each reflection zone's srcnat chain.
		// When dest_ip (10.0.0.2) falls within the reflection zone's own subnet, fw4
		// uses the matching zone gateway; otherwise it uses the zone's own gateway.
		// lan  (10.0.0.1/24 covers dest_ip 10.0.0.2) → snat 10.0.0.1
		// guest (10.1.0.1/24 does not cover dest_ip)  → snat 10.1.0.1
		const srcnat_lan   = extractChain(nft, 'srcnat_lan');
		const srcnat_guest = extractChain(nft, 'srcnat_guest');
		assert.match(truthy(), srcnat_lan   !== null);
		assert.match(truthy(), srcnat_guest !== null);
		assert.match(contains('snat 10.0.0.1'), srcnat_lan);
		assert.match(contains('snat 10.1.0.1'), srcnat_guest);
		// dstnat reflection rules appear in each reflection zone's dstnat chain
		assert.match(contains('dnat 10.0.0.2:22'), extractChain(nft, 'dstnat_lan'));
		assert.match(contains('dnat 10.0.0.2:22'), extractChain(nft, 'dstnat_guest'));
	});

	it('non-contiguous src_ip mask in a redirect with reflection_zone: bitwise expression propagates to all dstnat chains', () => {
		// src_ip '10.0.0.1/255.0.0.255' is a non-contiguous mask that cannot be expressed
		// as a CIDR prefix; fw4 renders it as 'ip saddr & 255.0.0.255 == 10.0.0.1'.
		// With reflection_zone, this bitwise expression must appear in both the wan DNAT
		// chain and the lan reflection DNAT chain.
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wan', network: ['wan'], masq: '1', auto_helper: 0 },
				'@zone[1]': { '.type': 'zone', name: 'lan', network: ['lan'], auto_helper: 0 },
				'@redirect[0]': { '.type': 'redirect', name: 'r', src: 'wan', dest: 'lan',
				                  proto: 'tcp', dest_port: '22',
				                  dest_ip: '192.168.26.100',
				                  src_ip: '10.0.0.1/255.0.0.255',
				                  reflection_zone: ['lan'] }
			},
			helpers: {}
		}});
		const nft = renderWith();
		// Main DNAT chain in dstnat_wan: src_ip non-contiguous mask renders as bitwise & expression
		const dstnat_wan = extractChain(nft, 'dstnat_wan');
		assert.match(truthy(), dstnat_wan !== null);
		assert.match(contains('ip saddr & 255.0.0.255 == 10.0.0.1'), dstnat_wan);
		// Reflection DNAT chain in the lan zone is generated despite the masked src_ip.
		// The reflection rule uses the zone subnets as the match (not the original src_ip mask),
		// because it targets LAN-to-LAN hairpin traffic via the WAN address.
		const dstnat_lan = extractChain(nft, 'dstnat_lan');
		assert.match(truthy(), dstnat_lan !== null);
		assert.match(contains('dnat 192.168.26.100:22'), dstnat_lan);
	});
});

