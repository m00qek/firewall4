'use strict';

// Rule rendering: direction, enabled/disabled, constraints, ICMP, mangle,
// subnet masks, family inheritance, time, notrack, log, and mark.
// Redirect (DNAT/SNAT) rules live in ruleset_redirects_test.uc.

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

describe('rules — direction', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('rule with src: * is placed in the input chain', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', proto: 'tcp', src: '*', dest_port: '22', target: 'accept' } },
			helpers: {}
		}});
		assert.match(contains('tcp dport 22 counter accept'), extractChain(renderWith(), 'input'));
	});

	it('rule with dest: * is placed in the output chain', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', proto: 'tcp', dest: '*', dest_port: '22', target: 'accept' } },
			helpers: {}
		}});
		assert.match(contains('tcp dport 22 counter accept'), extractChain(renderWith(), 'output'));
	});

	it('rule with src: * and dest: * is placed in the forward chain', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', proto: 'tcp', src: '*', dest: '*', dest_port: '22', target: 'accept' } },
			helpers: {}
		}});
		assert.match(contains('tcp dport 22 counter accept'), extractChain(renderWith(), 'forward'));
	});

	it('rule with neither src nor dest is placed in the output chain', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', proto: 'tcp', dest_port: '22', target: 'accept' } },
			helpers: {}
		}});
		assert.match(contains('tcp dport 22 counter accept'), extractChain(renderWith(), 'output'));
	});
});

describe('rules — enabled', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('rules are enabled by default and when enabled: 1', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'Implicit',  proto: 'any', src: '*' },
				'@rule[1]': { '.type': 'rule', name: 'Explicit',  proto: 'any', src: '*', enabled: '1' }
			},
			helpers: {}
		}});
		const input = extractChain(renderWith(), 'input');
		assert.match(contains('Implicit'), input);
		assert.match(contains('Explicit'), input);
	});

	it('rule with enabled: 0 is omitted from the ruleset', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'Disabled', proto: 'any', src: '*', enabled: '0' } },
			helpers: {}
		}});
		assert.match(not(contains('Disabled')), renderWith());
	});
});

describe('rules — constraints', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('helper rule without an explicit source zone is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'lan' },
				'@rule[0]': { '.type': 'rule', name: 'Bad helper', proto: 'any', target: 'helper' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad helper')), renderWith());
	});

	it('helper rule without set_helper is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'lan' },
				'@rule[0]': { '.type': 'rule', name: 'Bad helper 2', proto: 'any', src: 'lan', target: 'helper' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad helper 2')), renderWith());
	});

	it('notrack rule without an explicit source zone is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'Bad notrack', proto: 'any', target: 'NOTRACK' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad notrack')), renderWith());
	});

	it('DSCP target rule without set_dscp is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'Bad DSCP', proto: 'any', src: '*', target: 'DSCP' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad DSCP')), renderWith());
	});

	it('mark rule without set_mark or set_xmark is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'Bad mark', proto: 'any', src: '*', target: 'MARK' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad mark')), renderWith());
	});

	it('DSCP match rule generates per-family output rules', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'DSCP', proto: 'any', dscp: '0x0' }
			},
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('nfproto ipv4'), output);
		assert.match(contains('nfproto ipv6'), output);
	});
});

describe('rules — ICMP protocol', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('proto: icmp generates rules for both icmp and ipv6-icmp', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', proto: 'icmp' } },
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('"icmp"'),        output);
		assert.match(contains('"ipv6-icmp"'),   output);
	});

	it('proto: icmpv6 generates an IPv6-only rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', proto: 'icmpv6' } },
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('ipv6-icmp'),            output);
		assert.match(not(contains('nfproto ipv4')),    output);
	});

	it('icmp with an IPv4-specific type suppresses the IPv6 rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', proto: 'icmp', icmp_type: ['ip-header-bad'] } },
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('nfproto ipv4'),         output);
		assert.match(not(contains('ipv6-icmp')),       output);
	});

	it('icmp with an IPv6-specific type suppresses the IPv4 rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', proto: 'icmp', icmp_type: ['neighbour-solicitation'] } },
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('icmpv6'),               output);
		assert.match(not(contains('nfproto ipv4')),    output);
	});

	it('proto: ipv6-icmp is an alias for icmpv6', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', proto: 'ipv6-icmp' } },
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('ipv6-icmp'),            output);
		assert.match(not(contains('nfproto ipv4')),    output);
	});

	it('numeric type/code format generates a combined-key icmpv6 type . code match', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', src: '*', proto: 'icmpv6',
			                          icmp_type: ['130/0', '131/0'], target: 'accept' } },
			helpers: {}
		}});
		assert.match(contains('icmpv6 type . icmpv6 code { 130 . 0, 131 . 0 }'),
			extractChain(renderWith(), 'input'));
	});
});

describe('rules — pass-through protocols', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('proto: igmp generates a meta l4proto igmp rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', src: '*', proto: 'igmp', target: 'accept' } },
			helpers: {}
		}});
		assert.match(contains('meta l4proto igmp counter accept'), extractChain(renderWith(), 'input'));
	});

	it('proto: esp generates a meta l4proto esp rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: '*', proto: 'esp', target: 'accept' } },
			helpers: {}
		}});
		assert.match(contains('meta l4proto esp counter accept'), extractChain(renderWith(), 'forward'));
	});
});

describe('rules — mangle (DSCP)', () => {
	afterEach(() => mock.global.unpatch('uci'));

	const ZONES = {
		'@zone[0]': { '.type': 'zone', name: 'lan', device: ['eth0', 'eth1'] },
		'@zone[1]': { '.type': 'zone', name: 'wan', device: ['eth2', 'eth3'] }
	};

	it('src: * dest: * places the DSCP rule in mangle_forward', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: '*', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('ip dscp set 0x1'), extractChain(renderWith(), 'mangle_forward'));
	});

	it('src: zone dest: * places the DSCP rule in mangle_prerouting', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', src: 'lan', dest: '*', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('ip dscp set 0x1'), extractChain(renderWith(), 'mangle_prerouting'));
	});

	it('src: * dest: zone places the DSCP rule in mangle_postrouting', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: 'wan', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('ip dscp set 0x1'), extractChain(renderWith(), 'mangle_postrouting'));
	});

	it('src: zone dest: zone places the DSCP rule in mangle_forward with both iifname and oifname', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', src: 'lan', dest: 'wan', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'mangle_forward');
		assert.match(contains('iifname { "eth0", "eth1" }'), chain);
		assert.match(contains('oifname { "eth2", "eth3" }'), chain);
		assert.match(contains('ip dscp set 0x1'),             chain);
	});

	it('src: zone no dest places the DSCP rule in mangle_input', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', src: 'lan', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('ip dscp set 0x1'), extractChain(renderWith(), 'mangle_input'));
	});

	it('src: * no dest places the DSCP rule in mangle_input without an iifname constraint', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'mangle_input');
		assert.match(contains('ip dscp set 0x1'), chain);
		assert.match(not(contains('iifname')),    chain);
	});

	it('no src no dest places the DSCP rule in mangle_output', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('ip dscp set 0x1'), extractChain(renderWith(), 'mangle_output'));
	});

	it('no src dest: zone places the DSCP rule in mangle_output', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', dest: 'wan', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('ip dscp set 0x1'), extractChain(renderWith(), 'mangle_output'));
	});

	it('device option with no direction overrides the inbound ifname match', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: 'wan',
				              device: 'eth4', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('iifname "eth4"'), extractChain(renderWith(), 'mangle_postrouting'));
	});

	it('device with direction "in" overrides the inbound ifname match', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: 'wan',
				              device: 'eth4', direction: 'in', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('iifname "eth4"'), extractChain(renderWith(), 'mangle_postrouting'));
	});

	it('device with direction "out" overrides the outbound ifname match', () => {
		mock.global.patch('uci', { data: {
			firewall: { ...ZONES,
				'@rule[0]': { '.type': 'rule', name: 'r', src: '*', dest: 'wan',
				              device: 'eth5', direction: 'out', target: 'DSCP', set_dscp: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('oifname "eth5"'), extractChain(renderWith(), 'mangle_postrouting'));
	});
});

describe('rules — non-contiguous subnet masks', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.unpatch('ubus'); });

	it('non-contiguous src_ip and dest_ip masks generate bitwise match expressions', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all',
				              src_ip: '::1/::ffff', dest_ip: '!::2/::ffff' }
			},
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('ip6 saddr & ::ffff == ::1'),  output);
		assert.match(contains('ip6 daddr & ::ffff != ::2'),  output);
	});

	it('negative bitcount is treated as the complement mask', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all',
				              src_ip: '::1/-64', dest_ip: '!::2/-64' }
			},
			helpers: {}
		}});
		// -64 bit prefix → mask covers the upper 64 bits: ::ffff:ffff:ffff:ffff
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('ip6 saddr & ::ffff:ffff:ffff:ffff == ::1'),  output);
		assert.match(contains('ip6 daddr & ::ffff:ffff:ffff:ffff != ::2'),  output);
	});

	it('mix of masked and unmasked IPs in src_ip generates bitwise and set expressions', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all',
				              src_ip: ['::1/::ffff', '::3/128', '!::7/128'] }
			},
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		// Masked entry generates bitwise match
		assert.match(contains('ip6 saddr & ::ffff == ::1'),   output);
		// Exact /128 entries are grouped into an ip6 saddr set
		assert.match(contains('ip6 saddr ::3'),                output);
		// Negated exact entries use !=
		assert.match(contains('ip6 saddr != ::7'),             output);
	});

	it('masked src_ip and src_dip in a redirect generate bitwise match expressions in the dstnat rule', () => {
		mock.global.patch('ubus', { data: { 'network.interface:dump': { interface: [
			{ interface: 'wan',  up: true, l3_device: 'eth0', device: 'eth0',
			  'ipv6-address': [{ address: '2001:db8:54::2', mask: 64 }] },
			{ interface: 'lan',  up: true, l3_device: 'br-lan', device: 'br-lan',
			  'ipv6-prefix-assignment': [{ address: '2001:db8:1000::/60',
			    'local-address': { address: '2001:db8:1000::1', mask: 60 } }] }
		] } } });
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wan', network: ['wan'], auto_helper: 0 },
				'@zone[1]': { '.type': 'zone', name: 'lan', network: ['lan'], auto_helper: 0 },
				'@redirect[0]': { '.type': 'redirect', name: 'r', family: 'ipv6',
				                  src: 'wan', dest: 'lan',
				                  src_ip: '::1/::ffff', src_dip: '::9/::ffff',
				                  dest_ip: '::99', dest_port: '22', target: 'DNAT' }
			},
			helpers: {}
		}});
		const nft = renderWith();
		// dstnat rule uses bitwise & notation for both src_ip and src_dip
		const dstnat = extractChain(nft, 'dstnat_wan');
		assert.match(contains('ip6 saddr & ::ffff == ::1'), dstnat);
		assert.match(contains('ip6 daddr & ::ffff == ::9'), dstnat);
	});
});

describe('rules — family inheritance from zone', () => {
	afterEach(() => mock.global.unpatch('uci'));

	const IPV4ONLY = { '.type': 'zone', name: 'ipv4only', subnet: '192.168.1.0/24', auto_helper: 0 };

	it('rule referencing an IPv4-only zone is restricted to IPv4', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': IPV4ONLY,
				'@rule[0]': { '.type': 'rule', name: 'r', src: 'ipv4only', proto: 'tcp', dest_port: '22', target: 'accept' }
			},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'input_ipv4only');
		assert.match(contains('meta nfproto ipv4'),      chain);
		assert.match(not(contains('meta nfproto ipv6')), chain);
	});

	it('rule whose explicit family conflicts with its addresses is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'Bad rule', proto: 'tcp',
				              src_ip: '10.0.0.1', dest_port: '22', target: 'accept', family: 'IPv6' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad rule')), renderWith());
	});

	it('rule whose explicit family conflicts with the zone family is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': IPV4ONLY,
				'@rule[0]': { '.type': 'rule', name: 'Bad rule', src: 'ipv4only',
				              proto: 'tcp', dest_port: '22', target: 'accept', family: 'IPv6' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad rule')), renderWith());
	});

	it('rule whose explicit family conflicts with the referenced set family is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]':  IPV4ONLY,
				'@ipset[0]': { '.type': 'ipset', name: 'ipv4set', match: 'src_ip',
				               entry: ['10.0.0.2', '10.0.0.3'] },
				'@rule[0]':  { '.type': 'rule', name: 'Bad rule', src: 'ipv4only', proto: 'tcp',
				               ipset: 'ipv4set', target: 'accept', family: 'IPv6' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad rule')), renderWith());
	});

	it('zone with conflicting family and subnet is silently skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'bad', subnet: '10.0.0.0/8', family: 'IPv6', auto_helper: 0 }
			},
			helpers: {}
		}});
		assert.match(not(contains('chain input_bad')), renderWith());
	});

	it('redirect whose family conflicts with the zone family is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': IPV4ONLY,
				'@redirect[0]': { '.type': 'redirect', name: 'Bad redirect', src: 'ipv4only',
				                  proto: 'tcp', src_dport: '22', dest_port: '22', family: 'ipv6', target: 'dnat' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad redirect')), renderWith());
	});

	it('NAT whose family conflicts with the zone family is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': IPV4ONLY,
				'@nat[0]': { '.type': 'nat', name: 'Bad NAT', src: 'ipv4only', family: 'ipv6', target: 'masquerade' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad NAT')), renderWith());
	});

	it('NAT whose family conflicts with its addresses is skipped', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', masq: '1', auto_helper: 0 },
				'@nat[0]': { '.type': 'nat', name: 'Bad NAT', src: '*', src_ip: 'fc00::/7',
				             family: 'ipv4', target: 'masquerade' }
			},
			helpers: {}
		}});
		assert.match(not(contains('Bad NAT')), renderWith());
	});
});

describe('nat — family selection', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('NAT with no family and no AF-specific bits defaults to IPv4', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', masq: '1', auto_helper: 0 },
				'@nat[0]': { '.type': 'nat', name: 'NAT3', src: '*', target: 'masquerade' }
			},
			helpers: {}
		}});
		const srcnat = extractChain(renderWith(), 'srcnat');
		assert.match(contains('nfproto ipv4'),      srcnat);
		assert.match(not(contains('nfproto ipv6')), srcnat);
	});

	it('NAT with no family but IPv6-specific src_ip generates an IPv6 masquerade rule', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', masq: '1', auto_helper: 0 },
				'@nat[0]': { '.type': 'nat', name: 'NAT4', src: '*', src_ip: 'fc00::/7', target: 'masquerade' }
			},
			helpers: {}
		}});
		const srcnat = extractChain(renderWith(), 'srcnat');
		assert.match(contains('fc00::/7'),          srcnat);
		assert.match(not(contains('nfproto ipv4')), srcnat);
	});

	it('NAT with family: any referencing an IPv4-only zone inherits IPv4 restriction', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'ipv4only', subnet: '192.168.1.0/24', auto_helper: 0 },
				'@nat[0]': { '.type': 'nat', name: 'NAT5', src: 'ipv4only', family: 'any', target: 'masquerade' }
			},
			helpers: {}
		}});
		// @nat rules always land in the main srcnat chain (not a per-zone chain).
		const chain = extractChain(renderWith(), 'srcnat');
		assert.match(contains('nfproto ipv4'),      chain);
		assert.match(not(contains('nfproto ipv6')), chain);
	});

	it('NAT with family: any and no zone restriction generates a dual-stack masquerade', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', masq: '1', auto_helper: 0 },
				'@nat[0]': { '.type': 'nat', name: 'NAT6', src: '*', family: 'any', target: 'masquerade' }
			},
			helpers: {}
		}});
		const srcnat = extractChain(renderWith(), 'srcnat');
		assert.match(contains('masquerade'), srcnat);
		assert.match(not(contains('nfproto')), srcnat);
	});
});

describe('rules — time matching', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('full ISO datetime stamp is rendered as meta time >=', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all', start_date: '2022-05-30T21:51:23', target: 'ACCEPT' }
			},
			helpers: {}
		}});
		assert.match(contains('meta time >= "2022-05-30 21:51:23"'), extractChain(renderWith(), 'output'));
	});

	it('datetime without seconds is rounded down to the minute', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all', start_date: '2022-05-30T21:51', target: 'ACCEPT' }
			},
			helpers: {}
		}});
		assert.match(contains('meta time >= "2022-05-30 21:51:00"'), extractChain(renderWith(), 'output'));
	});

	it('partial date stamps are zero-padded to midnight on the first of the period', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', proto: 'all', start_date: '2022-05-30T21', target: 'ACCEPT' },
				'@rule[1]': { '.type': 'rule', proto: 'all', start_date: '2022-05-30',    target: 'ACCEPT' },
				'@rule[2]': { '.type': 'rule', proto: 'all', start_date: '2022-05',       target: 'ACCEPT' },
				'@rule[3]': { '.type': 'rule', proto: 'all', start_date: '2022',           target: 'ACCEPT' }
			},
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('meta time >= "2022-05-30 21:00:00"'), output);
		assert.match(contains('meta time >= "2022-05-30 00:00:00"'), output);
		assert.match(contains('meta time >= "2022-05-01 00:00:00"'), output);
		assert.match(contains('meta time >= "2022-01-01 00:00:00"'), output);
	});

	it('start_time generates a meta hour >= rule instead of meta time', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', proto: 'all', start_time: '21:51:23', target: 'ACCEPT' },
				'@rule[1]': { '.type': 'rule', proto: 'all', start_time: '21:51',    target: 'ACCEPT' },
				'@rule[2]': { '.type': 'rule', proto: 'all', start_time: '21',       target: 'ACCEPT' }
			},
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('meta hour >= "21:51:23"'), output);
		assert.match(contains('meta hour >= "21:51:00"'), output);
		assert.match(contains('meta hour >= "21:00:00"'), output);
	});

	it('start and stop date form a closed time range', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', proto: 'all',
				              start_date: '2022-05-30T21:51:23', stop_date: '2022-06-01T23:51:23', target: 'ACCEPT' }
			},
			helpers: {}
		}});
		assert.match(contains('meta time "2022-05-30 21:51:23"-"2022-06-01 23:51:23"'),
			extractChain(renderWith(), 'output'));
	});

	it('start and stop time form a closed hour range', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', proto: 'all',
				              start_time: '21:51:23', stop_time: '23:51:23', target: 'ACCEPT' }
			},
			helpers: {}
		}});
		assert.match(contains('meta hour "21:51:23"-"23:51:23"'), extractChain(renderWith(), 'output'));
	});

	it('weekdays generates a meta day set with normalised day names', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', proto: 'all',
				              weekdays: 'Monday tuEsday wed SUN Th', target: 'ACCEPT' }
			},
			helpers: {}
		}});
		const output = extractChain(renderWith(), 'output');
		assert.match(contains('meta day {'), output);
		assert.match(contains('"Monday"'),   output);
		assert.match(contains('"Tuesday"'),  output);
		assert.match(contains('"Sunday"'),   output);
	});
});

describe('rules — notrack', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.patch('fs', fs_patch()); });

	it('notrack rule with a regular device source is placed in raw_prerouting', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'z', device: ['eth0'], auto_helper: 0 },
				'@rule[0]': { '.type': 'rule', name: 'r', src: 'z', target: 'NOTRACK' }
			},
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('jump notrack_z'),          extractChain(nft, 'raw_prerouting'));
		assert.match(contains('meta l4proto tcp counter notrack'), extractChain(nft, 'notrack_z'));
		assert.match(contains('meta l4proto udp counter notrack'), extractChain(nft, 'notrack_z'));
	});

	it('notrack rule with the loopback device is placed in raw_output', () => {
		// Provide lo flags so fw4 recognises it as the loopback interface.
		mock.global.patch('fs',  fs_patch({ '/sys/class/net/lo/flags': '0x9' }));
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'z', device: ['lo'], auto_helper: 0 },
				'@rule[0]': { '.type': 'rule', name: 'r', src: 'z', target: 'NOTRACK' }
			},
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('jump notrack_z'),          extractChain(nft, 'raw_output'));
		assert.match(contains('meta l4proto tcp counter notrack'), extractChain(nft, 'notrack_z'));
		assert.match(contains('meta l4proto udp counter notrack'), extractChain(nft, 'notrack_z'));
	});

	it('notrack rule with a loopback source address is placed in raw_output', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'z', subnet: ['127.0.0.1/8', '::1/128'], auto_helper: 0 },
				'@rule[0]': { '.type': 'rule', name: 'r', src: 'z', target: 'NOTRACK' }
			},
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('jump notrack_z'),          extractChain(nft, 'raw_output'));
		assert.match(contains('meta l4proto tcp counter notrack'), extractChain(nft, 'notrack_z'));
		assert.match(contains('meta l4proto udp counter notrack'), extractChain(nft, 'notrack_z'));
	});
});

describe('rules — log prefix', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('log: 1 with a named rule uses the rule name as the log prefix', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'My Rule', proto: 'any', src: '*', log: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('log prefix "My Rule: "'), extractChain(renderWith(), 'input'));
	});

	it('log with an explicit string value uses that string as the prefix', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', proto: 'any', src: '*', log: 'Custom prefix: ' }
			},
			helpers: {}
		}});
		assert.match(contains('log prefix "Custom prefix: "'), extractChain(renderWith(), 'input'));
	});

	it('anonymous rule (no name) uses the section id as the log prefix', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', proto: 'any', src: '*', log: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('log prefix "@rule[0]: "'), extractChain(renderWith(), 'input'));
	});

	it('redirect with log: 1 emits a log statement before the dnat action', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]':     { '.type': 'zone', name: 'wan', device: 'eth0' },
				'@redirect[0]': { '.type': 'redirect', name: 'My Redirect',
				                  proto: 'tcp', src: 'wan', dest_ip: '10.0.0.2', dest_port: '22', log: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('log prefix "My Redirect: "'), extractChain(renderWith(), 'dstnat_wan'));
	});

	it('nat with log: 1 emits a log statement before the masquerade action', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wan', device: 'eth0', masq: '1' },
				'@nat[0]':  { '.type': 'nat', name: 'My NAT', src: 'wan', target: 'MASQUERADE', log: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('log prefix "My NAT: "'), extractChain(renderWith(), 'srcnat_wan'));
	});

	it('anonymous redirect uses the section id as the log prefix', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]':     { '.type': 'zone', name: 'wan', device: 'eth0' },
				'@redirect[0]': { '.type': 'redirect', proto: 'tcp', src: 'wan',
				                  dest_ip: '10.0.0.2', dest_port: '22', log: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('log prefix "@redirect[0]: "'), extractChain(renderWith(), 'dstnat_wan'));
	});

	it('redirect with explicit log string uses that string as the prefix', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]':     { '.type': 'zone', name: 'wan', device: 'eth0' },
				'@redirect[0]': { '.type': 'redirect', proto: 'tcp', src: 'wan',
				                  dest_ip: '10.0.0.2', dest_port: '22', log: 'Explicit prefix: ' }
			},
			helpers: {}
		}});
		assert.match(contains('log prefix "Explicit prefix: "'), extractChain(renderWith(), 'dstnat_wan'));
	});

	it('anonymous nat uses the section id as the log prefix', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wan', device: 'eth0', masq: '1' },
				'@nat[0]':  { '.type': 'nat', src: 'wan', target: 'MASQUERADE', log: '1' }
			},
			helpers: {}
		}});
		assert.match(contains('log prefix "@nat[0]: "'), extractChain(renderWith(), 'srcnat_wan'));
	});

	it('nat with explicit log string uses that string as the prefix', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'wan', device: 'eth0', masq: '1' },
				'@nat[0]':  { '.type': 'nat', src: 'wan', target: 'MASQUERADE', log: 'Explicit log prefix: ' }
			},
			helpers: {}
		}});
		assert.match(contains('log prefix "Explicit log prefix: "'), extractChain(renderWith(), 'srcnat_wan'));
	});
});

describe('rules — mark', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('set_mark sets the mark value directly', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all', src: '*', target: 'MARK', set_mark: '0xaa' }
			},
			helpers: {}
		}});
		assert.match(contains('meta mark set 0xaa'), extractChain(renderWith(), 'mangle_input'));
	});

	it('set_mark with a mask uses and/xor notation', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all', src: '*', target: 'MARK', set_mark: '0xab/0xff00' }
			},
			helpers: {}
		}});
		assert.match(contains('meta mark set mark and 0xffff0054 xor 0xab'), extractChain(renderWith(), 'mangle_input'));
	});

	it('set_xmark without mask sets the mark by XOR', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all', src: '*', target: 'MARK', set_xmark: '0xac' }
			},
			helpers: {}
		}});
		assert.match(contains('meta mark set 0xac'), extractChain(renderWith(), 'mangle_input'));
	});

	it('set_xmark with a mask uses and/xor notation', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all', src: '*', target: 'MARK', set_xmark: '0xad/0xff00' }
			},
			helpers: {}
		}});
		assert.match(contains('meta mark set mark and 0xffff00ff xor 0xad'), extractChain(renderWith(), 'mangle_input'));
	});

	it('set_xmark 0/mask ANDs bits using the and shorthand', () => {
		// set_xmark 0/mask means: keep only the bits where mask=0, i.e. AND with ~mask.
		// ~0xffffff51 = 0xae, so fw4 emits "mark set mark and 0xae".
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all', src: '*', target: 'MARK', set_xmark: '0/0xffffff51' }
			},
			helpers: {}
		}});
		assert.match(contains('meta mark set mark and 0xae'), extractChain(renderWith(), 'mangle_input'));
	});

	it('set_xmark with identical value and mask uses the or shorthand', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@rule[0]': { '.type': 'rule', name: 'r', proto: 'all', src: '*', target: 'MARK', set_xmark: '0xaf/0xaf' }
			},
			helpers: {}
		}});
		assert.match(contains('meta mark set mark or 0xaf'), extractChain(renderWith(), 'mangle_input'));
	});
});
