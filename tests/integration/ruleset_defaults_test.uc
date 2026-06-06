'use strict';

// Default firewall configuration rendering and rule ordering.

import { describe, it, assert, truthy, contains, not, afterEach, mock } from 'utest';

// ── Global module setup ─────────────────────────────────────────────────────

const _h = require('test_harness');
const extractChain = _h.extractChain;

const KERNEL   = 'Linux version 5.4.101 (build) #0 SMP Tue Mar 2 14:41:54 2021\n';
const NFT_JSON = '{"nftables":[{"metainfo":{"json_schema_version":1}}]}';

const IFACES = { interface: [
	{ interface: 'lan',  up: true, l3_device: 'br-lan',    device: 'br-lan',
	  'ipv4-address': [{ address: '10.0.0.1', mask: 24 }, { address: '192.168.26.1', mask: 24 }],
	  'ipv6-prefix-assignment': [{ address: 'fd00::/48',
	    'local-address': { address: 'fd00::1', mask: 48 } }] },
	{ interface: 'wan',  up: true, l3_device: 'pppoe-wan',  device: 'eth1',
	  'ipv4-address': [{ address: '10.11.12.194', mask: 24 }] },
	{ interface: 'wan6', up: true, l3_device: 'pppoe-wan',  device: 'eth1',
	  'ipv6-address': [{ address: '2001:db8:54:321::2', mask: 64 }] }
] };

// Base fs data required by every render.
const BASE_FILES    = { '/proc/version': KERNEL, '/sys/class/net/eth0/flags': '0x1003', '/sys/class/net/eth1/flags': '0x1003' };
const BASE_COMMANDS = { '/usr/sbin/nft --terse --json list flowtables inet': NFT_JSON };

// Returns a strict fs mock patch.  extra_data is merged over BASE_FILES.
// The readfile behavior handles arbitrary /sys/class/net/*/flags paths so that
// tests using wildcard or non-standard device names do not need to enumerate them.
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

describe('configuration — default ruleset', () => {
	// Each test patches all three mocks so afterEach always pops a test-level entry
	// rather than the module-level global patch.  Tests that don't need custom ubus
	// or fs data re-patch with empty / BASE_FILES+BASE_COMMANDS to maintain the stack invariant.
	afterEach(() => { mock.global.unpatch('uci'); mock.global.unpatch('fs'); mock.global.unpatch('ubus'); });

	it('syn_flood: 1 creates a syn_flood chain and jumps to it from input', () => {
		mock.global.patch('fs',   fs_patch());
		mock.global.patch('ubus', {});
		mock.global.patch('uci', { data: {
			firewall: {
				'@defaults[0]': { '.type': 'defaults', syn_flood: '1', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' },
				'@zone[0]':     { '.type': 'zone', name: 'wan', device: 'eth0', input: 'REJECT', auto_helper: 0 }
			},
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('jump syn_flood'),        extractChain(nft, 'input'));
		assert.match(contains('limit rate 25/second'),  extractChain(nft, 'syn_flood'));
	});

	it('flow_offloading: 1 declares a flowtable and adds flow offload to forward', () => {
		// related_physdevs is populated from network-based zones via ubus ifc.device.
		mock.global.patch('fs',  fs_patch());
		mock.global.patch('ubus', { data: { 'network.interface:dump': { interface: [
			{ interface: 'wan', up: true, l3_device: 'eth0', device: 'eth0',
			  'ipv4-address': [{ address: '10.0.0.1', mask: 24 }] }
		] } } });
		mock.global.patch('uci', { data: {
			firewall: {
				'@defaults[0]': { '.type': 'defaults', flow_offloading: '1', input: 'ACCEPT', output: 'ACCEPT', forward: 'ACCEPT' },
				'@zone[0]':     { '.type': 'zone', name: 'wan', network: 'wan', auto_helper: 0 }
			},
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('flowtable ft {'),    nft);
		assert.match(contains('flow offload @ft'),  extractChain(nft, 'forward'));
	});

	it('auto_helper assigns all ct helpers to zone traffic — each with proto+port match', () => {
		// Full helpers package — all 12 CT helpers, two of which share the h323 module.
		// RAS and Q.931 share the nf_conntrack_h323 kernel module.
		const HELPERS = {
			'@helper[0]':  { '.type': 'helper', name: 'amanda',    family: 'any',  module: 'nf_conntrack_amanda',     port: '10080', proto: 'udp' },
			'@helper[1]':  { '.type': 'helper', name: 'ftp',       family: 'any',  module: 'nf_conntrack_ftp',        port: '21',    proto: 'tcp' },
			'@helper[2]':  { '.type': 'helper', name: 'RAS',       family: 'any',  module: 'nf_conntrack_h323',       port: '1719',  proto: 'udp' },
			'@helper[3]':  { '.type': 'helper', name: 'Q.931',     family: 'any',  module: 'nf_conntrack_h323',       port: '1720',  proto: 'tcp' },
			'@helper[4]':  { '.type': 'helper', name: 'irc',       family: 'ipv4', module: 'nf_conntrack_irc',        port: '6667',  proto: 'tcp' },
			'@helper[5]':  { '.type': 'helper', name: 'netbios-ns',family: 'ipv4', module: 'nf_conntrack_netbios_ns', port: '137',   proto: 'udp' },
			'@helper[6]':  { '.type': 'helper', name: 'pptp',      family: 'ipv4', module: 'nf_conntrack_pptp',       port: '1723',  proto: 'tcp' },
			'@helper[7]':  { '.type': 'helper', name: 'sane',      family: 'any',  module: 'nf_conntrack_sane',       port: '6566',  proto: 'tcp' },
			'@helper[8]':  { '.type': 'helper', name: 'sip',       family: 'any',  module: 'nf_conntrack_sip',        port: '5060',  proto: 'udp' },
			'@helper[9]':  { '.type': 'helper', name: 'snmp',      family: 'ipv4', module: 'nf_conntrack_snmp',       port: '161',   proto: 'udp' },
			'@helper[10]': { '.type': 'helper', name: 'tftp',      family: 'any',  module: 'nf_conntrack_tftp',       port: '69',    proto: 'udp' },
			'@helper[11]': { '.type': 'helper', name: 'rtsp',      family: 'ipv4', module: 'nf_conntrack_rtsp',       port: '554',   proto: 'tcp' }
		};
		mock.global.patch('fs',  fs_patch({
			'/sys/module/nf_conntrack_amanda/exists':     '',
			'/sys/module/nf_conntrack_ftp/exists':        '',
			'/sys/module/nf_conntrack_h323/exists':       '',
			'/sys/module/nf_conntrack_irc/exists':        '',
			'/sys/module/nf_conntrack_netbios_ns/exists': '',
			'/sys/module/nf_conntrack_pptp/exists':       '',
			'/sys/module/nf_conntrack_sane/exists':       '',
			'/sys/module/nf_conntrack_sip/exists':        '',
			'/sys/module/nf_conntrack_snmp/exists':       '',
			'/sys/module/nf_conntrack_tftp/exists':       '',
			'/sys/module/nf_conntrack_rtsp/exists':       ''
		}));
		mock.global.patch('ubus', {});
		mock.global.patch('uci', { data: {
			firewall: {
				'@defaults[0]': { '.type': 'defaults', input: 'ACCEPT', output: 'ACCEPT', forward: 'ACCEPT' },
				// auto_helper is intentionally absent: it defaults to 1, which is what enables
				// the auto-helper assignment path being tested here.
				'@zone[0]':     { '.type': 'zone', name: 'wan', device: 'eth0' }
			},
			helpers: HELPERS
		}});
		const nft = renderWith();
		const helper_wan = extractChain(nft, 'helper_wan');
		// Every helper must have its ct helper type declared at the table level
		assert.match(contains('ct helper amanda {'),    nft);
		assert.match(contains('ct helper ftp {'),       nft);
		assert.match(contains('ct helper tftp {'),      nft);
		// Every helper must produce a proto+port-matched assignment rule in the zone helper chain
		assert.match(contains('meta l4proto udp udp dport 10080 ct helper set "amanda"'), helper_wan);
		assert.match(contains('meta l4proto tcp tcp dport 21 ct helper set "ftp"'),       helper_wan);
		assert.match(contains('meta l4proto udp udp dport 1719 ct helper set "RAS"'),     helper_wan);
		assert.match(contains('meta l4proto tcp tcp dport 1720 ct helper set "Q.931"'),   helper_wan);
		assert.match(contains('meta l4proto tcp tcp dport 6566 ct helper set "sane"'),    helper_wan);
		assert.match(contains('meta l4proto udp udp dport 5060 ct helper set "sip"'),     helper_wan);
		assert.match(contains('meta l4proto udp udp dport 69 ct helper set "tftp"'),      helper_wan);
		// IPv4-only helpers carry an nfproto qualifier before the proto+port match
		assert.match(contains('meta nfproto ipv4 meta l4proto tcp tcp dport 6667 ct helper set "irc"'),      helper_wan);
		assert.match(contains('meta nfproto ipv4 meta l4proto udp udp dport 137 ct helper set "netbios-ns"'), helper_wan);
		assert.match(contains('meta nfproto ipv4 meta l4proto tcp tcp dport 1723 ct helper set "pptp"'),      helper_wan);
		assert.match(contains('meta nfproto ipv4 meta l4proto udp udp dport 161 ct helper set "snmp"'),       helper_wan);
		assert.match(contains('meta nfproto ipv4 meta l4proto tcp tcp dport 554 ct helper set "rtsp"'),       helper_wan);
	});

	it('wan zone with masq: 1 generates an IPv4 masquerade rule in srcnat', () => {
		mock.global.patch('fs',   fs_patch());
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		mock.global.patch('uci', { data: {
			firewall: {
				'@defaults[0]': { '.type': 'defaults', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' },
				'@zone[0]':     { '.type': 'zone', name: 'wan', network: ['wan', 'wan6'], masq: '1', auto_helper: 0 }
			},
			helpers: {}
		}});
		assert.match(contains('meta nfproto ipv4 masquerade'), extractChain(renderWith(), 'srcnat_wan'));
	});

	it('mtu_fix: 1 generates TCP MSS clamping rules in mangle_postrouting and mangle_forward', () => {
		// Single pppoe-wan interface only — mtu_fix is a PPPoE-specific feature and the
		// test doesn't need the full IFACES topology (lan + wan + wan6).
		mock.global.patch('fs',   fs_patch());
		mock.global.patch('ubus', { data: { 'network.interface:dump': { interface: [
			{ interface: 'wan', up: true, l3_device: 'pppoe-wan', device: 'pppoe-wan',
			  'ipv4-address': [{ address: '10.11.12.194', mask: 24 }] }
		] } } });
		mock.global.patch('uci', { data: {
			firewall: {
				'@defaults[0]': { '.type': 'defaults', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' },
				'@zone[0]':     { '.type': 'zone', name: 'wan', network: ['wan'], mtu_fix: '1', auto_helper: 0 }
			},
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('tcp option maxseg size set rt mtu'), extractChain(nft, 'mangle_postrouting'));
		assert.match(contains('tcp option maxseg size set rt mtu'), extractChain(nft, 'mangle_forward'));
	});
});

describe('configuration — rule ordering', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.unpatch('fs'); mock.global.unpatch('ubus'); });

	// lan→wan topology with two deny rules followed by a forwarding — exercises both ordering properties.
	const FIREWALL = {
		'@defaults[0]': { '.type': 'defaults', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' },
		'@zone[0]':     { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0 },
		'@zone[1]':     { '.type': 'zone', name: 'wan', network: ['wan', 'wan6'], auto_helper: 0 },
		'@forwarding[0]': { '.type': 'forwarding', src: 'lan', dest: 'wan' },
		'@rule[0]': { '.type': 'rule', name: 'Deny rule #1', proto: 'any',
		              src: 'lan', dest: 'wan', src_ip: '192.168.1.2', target: 'drop' },
		'@rule[1]': { '.type': 'rule', name: 'Deny rule #2', proto: 'icmp',
		              src: 'lan', dest: 'wan', src_ip: '192.168.1.3', target: 'drop' }
	};

	it('config rule entries are rendered before config forwarding entries in the forward chain', () => {
		mock.global.patch('fs',   fs_patch());
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		mock.global.patch('uci',  { data: { firewall: FIREWALL, helpers: {} } });
		const forward_lan = extractChain(renderWith(), 'forward_lan');
		const deny1_pos   = index(forward_lan, 'ip saddr 192.168.1.2');
		const deny2_pos   = index(forward_lan, 'ip saddr 192.168.1.3');
		const fwd_pos     = index(forward_lan, 'jump accept_to_wan');
		assert.match(truthy(), deny1_pos >= 0);
		assert.match(truthy(), deny2_pos >= 0);
		assert.match(truthy(), fwd_pos   >= 0);
		assert.match(truthy(), deny1_pos < fwd_pos);
		assert.match(truthy(), deny2_pos < fwd_pos);
	});

	it('rules are rendered in declaration order', () => {
		mock.global.patch('fs',   fs_patch());
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		mock.global.patch('uci',  { data: { firewall: FIREWALL, helpers: {} } });
		const forward_lan = extractChain(renderWith(), 'forward_lan');
		assert.match(truthy(), index(forward_lan, 'ip saddr 192.168.1.2') < index(forward_lan, 'ip saddr 192.168.1.3'));
	});
});

describe('configuration — table preamble', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.unpatch('fs'); mock.global.unpatch('ubus'); });

	it('rendered output starts with the flush preamble followed by the table definition', () => {
		mock.global.patch('fs',   fs_patch());
		mock.global.patch('ubus', {});
		mock.global.patch('uci',  { data: {
			firewall: { '@defaults[0]': { '.type': 'defaults', input: 'ACCEPT', output: 'ACCEPT', forward: 'ACCEPT' } },
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(truthy(), index(nft, 'table inet fw4\nflush table inet fw4') == 0);
		assert.match(contains('table inet fw4 {'), nft);
	});
});

describe('configuration — default wan zone service rules', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.unpatch('fs'); mock.global.unpatch('ubus'); });

	const DEFAULTS = { '.type': 'defaults', input: 'REJECT', output: 'ACCEPT', forward: 'REJECT' };
	const WAN_ZONE = { '.type': 'zone', name: 'wan', device: 'eth0', input: 'REJECT', forward: 'REJECT', auto_helper: 0 };

	it('Allow-DHCP-Renew: IPv4 UDP to port 68 accepted on input_wan', () => {
		mock.global.patch('fs',  fs_patch());
		mock.global.patch('ubus', {});
		mock.global.patch('uci', { data: {
			firewall: {
				'@defaults[0]': DEFAULTS,
				'@zone[0]':     WAN_ZONE,
				'@rule[0]': { '.type': 'rule', name: 'Allow-DHCP-Renew',
				              src: 'wan', proto: 'udp', dest_port: '68', target: 'ACCEPT', family: 'ipv4' }
			},
			helpers: {}
		}});
		assert.match(contains('meta nfproto ipv4 udp dport 68 counter accept'),
			extractChain(renderWith(), 'input_wan'));
	});

	it('Allow-Ping: IPv4 ICMP echo-request accepted on input_wan', () => {
		mock.global.patch('fs',  fs_patch());
		mock.global.patch('ubus', {});
		mock.global.patch('uci', { data: {
			firewall: {
				'@defaults[0]': DEFAULTS,
				'@zone[0]':     WAN_ZONE,
				'@rule[0]': { '.type': 'rule', name: 'Allow-Ping',
				              src: 'wan', proto: 'icmp', icmp_type: 'echo-request', target: 'ACCEPT', family: 'ipv4' }
			},
			helpers: {}
		}});
		assert.match(contains('meta nfproto ipv4 icmp type 8 counter accept'),
			extractChain(renderWith(), 'input_wan'));
	});

	it('Allow-ICMPv6-Input: IPv6 ICMPv6 types with rate limit accepted on input_wan', () => {
		mock.global.patch('fs',  fs_patch());
		mock.global.patch('ubus', {});
		mock.global.patch('uci', { data: {
			firewall: {
				'@defaults[0]': DEFAULTS,
				'@zone[0]':     WAN_ZONE,
				'@rule[0]': { '.type': 'rule', name: 'Allow-ICMPv6-Input', src: 'wan',
				              proto: 'icmp', family: 'ipv6', limit: '1000/sec', target: 'ACCEPT',
				              icmp_type: ['echo-request', 'echo-reply', 'destination-unreachable',
				                          'time-exceeded', 'router-solicitation', 'router-advertisement'] }
			},
			helpers: {}
		}});
		const input_wan = extractChain(renderWith(), 'input_wan');
		assert.match(contains('meta nfproto ipv6 icmpv6 type { 128, 129, 1, 3, 133, 134 }'), input_wan);
		assert.match(contains('limit rate 1000/second counter accept'), input_wan);
	});

	it('Allow-ICMPv6-Forward: IPv6 ICMPv6 types with rate limit accepted on forward_wan', () => {
		mock.global.patch('fs',  fs_patch());
		mock.global.patch('ubus', {});
		mock.global.patch('uci', { data: {
			firewall: {
				'@defaults[0]': DEFAULTS,
				'@zone[0]':     WAN_ZONE,
				'@rule[0]': { '.type': 'rule', name: 'Allow-ICMPv6-Forward', src: 'wan', dest: '*',
				              proto: 'icmp', family: 'ipv6', limit: '1000/sec', target: 'ACCEPT',
				              icmp_type: ['echo-request', 'echo-reply', 'destination-unreachable', 'time-exceeded'] }
			},
			helpers: {}
		}});
		const forward_wan = extractChain(renderWith(), 'forward_wan');
		assert.match(contains('meta nfproto ipv6 icmpv6 type { 128, 129, 1, 3 }'), forward_wan);
		assert.match(contains('limit rate 1000/second counter accept'), forward_wan);
	});
});
