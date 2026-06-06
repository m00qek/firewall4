'use strict';

// Zone-level ruleset behavior: policies, masquerade, wildcard devices, subnet
// masks, family selection, CT helpers, and log rate-limiting.

import { describe, it, assert, truthy, regex, contains, not, afterEach, mock } from 'utest';

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

describe('zones — input/output/forward policies', () => {
	// Tests here only patch uci, so afterEach only needs to unpatch uci.
	// If a future test adds an fs or ubus patch, extend the afterEach to match.
	afterEach(() => mock.global.unpatch('uci'));

	it('accept policy jumps to accept chains that counter-accept matched traffic', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', input: 'ACCEPT', output: 'ACCEPT', forward: 'ACCEPT', device: 'eth0' } },
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('jump accept_from_z'), extractChain(nft, 'input_z'));
		assert.match(contains('jump accept_to_z'),   extractChain(nft, 'output_z'));
		assert.match(contains('jump accept_to_z'),   extractChain(nft, 'forward_z'));
		assert.match(contains('counter accept'),     extractChain(nft, 'accept_from_z'));
		assert.match(contains('counter accept'),     extractChain(nft, 'accept_to_z'));
	});

	it('drop policy jumps to drop chains that counter-drop matched traffic', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', input: 'DROP', output: 'DROP', forward: 'DROP', device: 'eth0' } },
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('jump drop_from_z'), extractChain(nft, 'input_z'));
		assert.match(contains('jump drop_to_z'),   extractChain(nft, 'output_z'));
		assert.match(contains('jump drop_to_z'),   extractChain(nft, 'forward_z'));
		assert.match(contains('counter drop'),     extractChain(nft, 'drop_from_z'));
		assert.match(contains('counter drop'),     extractChain(nft, 'drop_to_z'));
	});

	it('reject policy jumps to handle_reject via per-direction chains', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', input: 'REJECT', output: 'REJECT', forward: 'REJECT', device: 'eth0' } },
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('jump reject_from_z'),        extractChain(nft, 'input_z'));
		assert.match(contains('jump reject_to_z'),          extractChain(nft, 'output_z'));
		assert.match(contains('jump reject_to_z'),          extractChain(nft, 'forward_z'));
		assert.match(contains('counter jump handle_reject'), extractChain(nft, 'reject_from_z'));
		assert.match(contains('counter jump handle_reject'), extractChain(nft, 'reject_to_z'));
	});
});

describe('zones — masquerade', () => {
	// Tests here only patch uci, so afterEach only needs to unpatch uci.
	// If a future test adds an fs or ubus patch, extend the afterEach to match.
	afterEach(() => mock.global.unpatch('uci'));

	it('masq: 1 emits an IPv4 srcnat masquerade rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'wan', output: 'ACCEPT', device: 'eth0', masq: '1' } },
			helpers: {}
		}});
		assert.match(contains('meta nfproto ipv4 masquerade'), extractChain(renderWith(), 'srcnat_wan'));
	});

	it('masq6: 1 emits an IPv6 srcnat masquerade rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'wan', output: 'ACCEPT', device: 'eth0', masq6: '1' } },
			helpers: {}
		}});
		assert.match(contains('meta nfproto ipv6 masquerade'), extractChain(renderWith(), 'srcnat_wan'));
	});

	it('both masq and masq6 emit IPv4 and IPv6 masquerade rules', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'wan', output: 'ACCEPT', device: 'eth0', masq: '1', masq6: '1' } },
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'srcnat_wan');
		assert.match(contains('meta nfproto ipv4 masquerade'), chain);
		assert.match(contains('meta nfproto ipv6 masquerade'), chain);
	});

	it('masq_src and masq_dest add address filters before the masquerade rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'wan', output: 'ACCEPT', device: 'eth0', masq: '1',
				masq_src:  ['10.1.0.0/24', '!10.1.0.1'],
				masq_dest: ['10.2.0.0/24', '!10.2.0.1']
			}},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'srcnat_wan');
		assert.match(contains('ip saddr 10.1.0.0/24'), chain);
		assert.match(contains('ip saddr != 10.1.0.1'), chain);
		assert.match(contains('ip daddr 10.2.0.0/24'), chain);
		assert.match(contains('masquerade'),           chain);
		// address filters must precede the masquerade action in the chain
		assert.match(truthy(), index(chain, 'ip saddr 10.1.0.0/24') < index(chain, 'masquerade'));
		assert.match(truthy(), index(chain, 'ip daddr 10.2.0.0/24') < index(chain, 'masquerade'));
	});

	it('masq: 1 filters IPv6 addresses out of masq_src and masq_dest', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'wan', output: 'ACCEPT', device: 'eth0', masq: '1',
				masq_src:  ['10.1.0.0/24', '2001:db8::/64'],
				masq_dest: ['10.2.0.0/24', '2001:db8:1::/64']
			}},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'srcnat_wan');
		assert.match(contains('ip saddr 10.1.0.0/24'),          chain);
		assert.match(contains('ip daddr 10.2.0.0/24'),          chain);
		assert.match(not(contains('2001:db8::/64')),            chain);
		assert.match(not(contains('2001:db8:1::/64')),          chain);
	});

	it('masq6: 1 filters IPv4 addresses out of masq_src and masq_dest', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'wan', output: 'ACCEPT', device: 'eth0', masq6: '1',
				masq_src:  ['10.1.0.0/24', '2001:db8::/64'],
				masq_dest: ['10.2.0.0/24', '2001:db8:1::/64']
			}},
			helpers: {}
		}});
		const chain = extractChain(renderWith(), 'srcnat_wan');
		assert.match(contains('ip6 saddr 2001:db8::/64'),       chain);
		assert.match(contains('ip6 daddr 2001:db8:1::/64'),     chain);
		assert.match(not(contains('10.1.0.0/24')),              chain);
		assert.match(not(contains('10.2.0.0/24')),              chain);
	});

	it('masq without masq_allow_invalid adds ct state invalid drop in the accept chain', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'wan', output: 'ACCEPT', device: 'eth0', masq: '1' } },
			helpers: {}
		}});
		assert.match(contains('ct state invalid'), extractChain(renderWith(), 'accept_to_wan'));
	});

	it('masq_allow_invalid: 1 removes the ct state invalid drop guard', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'wan', output: 'ACCEPT', device: 'eth0', masq: '1', masq_allow_invalid: 1 } },
			helpers: {}
		}});
		const accept_to_wan = extractChain(renderWith(), 'accept_to_wan');
		assert.match(truthy(), accept_to_wan !== null);
		assert.match(not(contains('ct state invalid')), accept_to_wan);
	});
});

describe('zones — wildcard device patterns', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('"+" device matches all interfaces (no iifname constraint in jump)', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: ['+'] } },
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(not(regex(/iifname.*jump input_z/)), extractChain(nft, 'input'));
		assert.match(truthy(), extractChain(nft, 'input_z'));
	});

	it('"!+" is an always-fail match expressed as iifname "/never/"', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: ['!+'] } },
			helpers: {}
		}});
		assert.match(contains('iifname "/never/" jump input_z'), extractChain(renderWith(), 'input'));
	});

	it('"prefix+" is translated to an nftables wildcard pattern', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: ['eth+'] } },
			helpers: {}
		}});
		assert.match(contains('iifname "eth*" jump input_z'), extractChain(renderWith(), 'input'));
	});

	it('multiple wildcard devices generate separate iifname rules, not a set', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: ['foo+', 'bar+', 'eth0', 'eth1'] } },
			helpers: {}
		}});
		const input = extractChain(renderWith(), 'input');
		// wildcards cannot be grouped — each gets its own jump rule
		assert.match(contains('iifname "foo*" jump input_z'), input);
		assert.match(contains('iifname "bar*" jump input_z'), input);
		// plain devices can be grouped into a set
		assert.match(contains('iifname { "eth0", "eth1" } jump input_z'), input);
	});

	it('multiple inverted wildcard and plain device exclusions are combined into one rule', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z',
			                         device: ['foo+', 'bar+', '!baz+', '!qrx+', 'eth0', '!eth1', '!eth2'] } },
			helpers: {}
		}});
		const input = extractChain(renderWith(), 'input');
		// Each positive wildcard produces a rule that carries all negations
		assert.match(contains('iifname "foo*" iifname != { "eth1", "eth2" } iifname != "baz*" iifname != "qrx*"'), input);
		assert.match(contains('iifname "bar*" iifname != { "eth1", "eth2" } iifname != "baz*" iifname != "qrx*"'), input);
	});
});

describe('zones — subnet mask matches', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('non-contiguous mask uses bitwise matching instead of CIDR notation', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', subnet: ['::1/::ffff', '!::2/::ffff'] } },
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('ip6 saddr & ::ffff == ::1'), extractChain(nft, 'input'));
		assert.match(contains('ip6 saddr & ::ffff != ::2'), extractChain(nft, 'input'));
	});

	it('masked entries are not grouped into sets — each generates a separate jump rule', () => {
		// Mixed: masked IPs (generate & expressions), exact IPs (go into sets),
		// negated masked IPs (generate != expressions). Because masked entries cannot
		// be combined into a single nftables set, fw4 produces one jump rule per
		// masked positive entry, each carrying all the negation conditions.
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', subnet: [
				'::1/::ffff', '::2/::ffff',   // masked → separate rules
				'::3/128',    '::4/128',       // exact → grouped into set
				'!::5/::ffff','!::6/::ffff',   // negated masked → != per rule
				'!::7/128',   '!::8/128'       // negated exact → != set
			] } },
			helpers: {}
		}});
		const input = extractChain(renderWith(), 'input');
		// Each masked positive entry generates its own jump rule
		assert.match(contains('ip6 saddr & ::ffff == ::1'), input);
		assert.match(contains('ip6 saddr & ::ffff == ::2'), input);
		// Exact addresses are grouped into an ip6 saddr set
		assert.match(contains('ip6 saddr { ::3, ::4 }'),   input);
		// Negated masked entries become != conditions on every rule
		assert.match(contains('ip6 saddr & ::ffff != ::5'), input);
		assert.match(contains('ip6 saddr & ::ffff != ::6'), input);
		// Negated exact entries become a != set
		assert.match(contains('ip6 saddr != { ::7, ::8 }'), input);
	});
});

describe('zones — address family selection', () => {
	afterEach(() => mock.global.unpatch('uci'));

	it('zone with only IPv4 subnets generates IPv4-only match rules', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', family: 'any', subnet: ['10.0.0.0/8'], auto_helper: 0 } },
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('meta nfproto ipv4'), extractChain(nft, 'input'));
		assert.match(not(contains('nfproto ipv6')), extractChain(nft, 'input'));
	});

	it('zone with only IPv6 subnets generates IPv6-only match rules', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', family: 'any', subnet: ['2001:db8::/32'], auto_helper: 0 } },
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('meta nfproto ipv6'), extractChain(nft, 'input'));
		assert.match(not(contains('nfproto ipv4')), extractChain(nft, 'input'));
	});

	it('explicit family: ipv6 restricts rules to IPv6 even with a device match', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', family: 'ipv6', device: ['eth0'], auto_helper: 0 } },
			helpers: {}
		}});
		assert.match(contains('meta nfproto ipv6 iifname "eth0" jump input_z'),
			extractChain(renderWith(), 'input'));
	});

	it('family: ipv6 zone with an IPv4 subnet emits no rules (conflicting family and subnet)', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', family: 'ipv6', subnet: ['10.0.0.0/8'], auto_helper: 0 } },
			helpers: {}
		}});
		assert.match(not(contains('jump input_z')), extractChain(renderWith(), 'input'));
	});

	it('family: ipv6 with no subnets generates IPv6-only rules', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', family: 'ipv6', device: 'eth0', auto_helper: 0 } },
			helpers: {}
		}});
		const input = extractChain(renderWith(), 'input');
		assert.match(contains('nfproto ipv6'),     input);
		assert.match(not(contains('nfproto ipv4')), input);
	});

	it('CT helper family restrictions do not influence the zone family selection', () => {
		// A zone with an IPv4 helper assigned still operates as dual-stack when
		// its own subnets are dual-stack (the helper family is irrelevant to zone family).
		mock.global.patch('fs',  fs_patch({ '/sys/module/nf_conntrack_irc/exists': '' }));
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', helper: ['irc'], auto_helper: 0 } },
			helpers:  { '@helper[0]': { '.type': 'helper', name: 'irc', family: 'ipv4',
			                            module: 'nf_conntrack_irc', port: '6667', proto: 'tcp' } }
		}});
		const input = extractChain(renderWith(), 'input');
		assert.match(not(contains('nfproto ipv4')), input);
		assert.match(not(contains('nfproto ipv6')), input);
		assert.match(contains('jump input_z'),       input);
	});
});

describe('zones — CT helpers', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.patch('fs', fs_patch()); });

	const TFTP = { '.type': 'helper', name: 'tftp', family: 'any',
	               module: 'nf_conntrack_tftp', port: '69', proto: 'udp' };

	it('explicit helper assignment emits a proto+port-matched ct helper set rule in the zone helper chain', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', masq: '1', helper: ['tftp'] } },
			helpers:  { '@helper[0]': TFTP }
		}});
		mock.global.patch('fs', fs_patch({ '/sys/module/nf_conntrack_tftp/exists': '' }));
		assert.match(contains('meta l4proto udp udp dport 69 ct helper set "tftp"'),
			extractChain(renderWith(), 'helper_z'));
	});

	it('explicit helper: [tftp] assigns only tftp — other available helpers are not auto-added', () => {
		const FTP = { '.type': 'helper', name: 'ftp', family: 'any',
		              module: 'nf_conntrack_ftp', port: '21', proto: 'tcp' };
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', helper: ['tftp'] } },
			helpers:  { '@helper[0]': TFTP, '@helper[1]': FTP }
		}});
		mock.global.patch('fs', fs_patch({
			'/sys/module/nf_conntrack_tftp/exists': '',
			'/sys/module/nf_conntrack_ftp/exists':  ''
		}));
		const helper_z = extractChain(renderWith(), 'helper_z');
		assert.match(contains('ct helper set "tftp"'),     helper_z);
		assert.match(not(contains('ct helper set "ftp"')), helper_z);
	});

	it('ct helper definition is declared in the table', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', helper: ['tftp'] } },
			helpers:  { '@helper[0]': TFTP }
		}});
		mock.global.patch('fs', fs_patch({ '/sys/module/nf_conntrack_tftp/exists': '' }));
		assert.match(contains('ct helper tftp {'), renderWith());
	});

	it('helper chain is emitted when masq6: 1 (IPv6 masquerade)', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', masq6: '1', helper: ['tftp'] } },
			helpers:  { '@helper[0]': TFTP }
		}});
		mock.global.patch('fs', fs_patch({ '/sys/module/nf_conntrack_tftp/exists': '' }));
		assert.match(contains('meta l4proto udp udp dport 69 ct helper set "tftp"'),
			extractChain(renderWith(), 'helper_z'));
	});

	it('helper chain is emitted even when both masq and masq6 are disabled', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0',
			                         masq: '0', masq6: '0', helper: ['tftp'] } },
			helpers:  { '@helper[0]': TFTP }
		}});
		mock.global.patch('fs', fs_patch({ '/sys/module/nf_conntrack_tftp/exists': '' }));
		assert.match(contains('meta l4proto udp udp dport 69 ct helper set "tftp"'),
			extractChain(renderWith(), 'helper_z'));
	});

	it('masq: 1 suppresses auto-helper assignment (no helper chain without explicit helper)', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', masq: '1' } },
			helpers:  { '@helper[0]': TFTP }
		}});
		mock.global.patch('fs', fs_patch({ '/sys/module/nf_conntrack_tftp/exists': '' }));
		assert.match(not(contains('ct helper set')), renderWith());
	});

	it('masq6: 1 also suppresses auto-helper assignment', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', masq6: '1' } },
			helpers:  { '@helper[0]': TFTP }
		}});
		mock.global.patch('fs', fs_patch({ '/sys/module/nf_conntrack_tftp/exists': '' }));
		assert.match(not(contains('ct helper set')), renderWith());
	});

	it('masq=0 masq6=0 with no explicit helper triggers auto-helper assignment', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', masq: '0', masq6: '0' } },
			helpers:  { '@helper[0]': TFTP }
		}});
		mock.global.patch('fs', fs_patch({ '/sys/module/nf_conntrack_tftp/exists': '' }));
		assert.match(contains('meta l4proto udp udp dport 69 ct helper set "tftp"'),
			extractChain(renderWith(), 'helper_z'));
	});

	it('unknown helper name causes the zone to be fully skipped — no zone chains are emitted', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'z', device: 'eth0', helper: ['foo'] } },
			helpers:  { '@helper[0]': TFTP }
		}});
		mock.global.patch('fs', fs_patch({ '/sys/module/nf_conntrack_tftp/exists': '' }));
		const nft = renderWith();
		assert.match(not(contains('chain input_z')),     nft);
		assert.match(not(contains('ct helper set "foo"')), nft);
	});
});

describe('zones — log rate limiting', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.unpatch('ubus'); });

	const IFACES = { interface: [
		{ interface: 'lan', up: true, l3_device: 'br-lan', device: 'br-lan',
		  'ipv4-address': [{ address: '10.0.0.1', mask: 24 }] }
	] };

	// Port numbers in these tests are arbitrary; they are kept unique across tests
	// so that each test's rule is identifiable in the rendered chain output.

	it('log_limit declares a named limit object in the table', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, log: 1, log_limit: '1/min' } },
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		assert.match(contains('limit lan.log_limit {'), renderWith());
	});

	it('zone drop+log: named limit appears in the input (drop_from) chain', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, input: 'DROP', log: 1, log_limit: '1/min' } },
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		assert.match(contains('limit name "lan.log_limit"'), extractChain(renderWith(), 'drop_from_lan'));
	});

	it('zone drop+log: named limit appears in the forward/output (drop_to) chain', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, forward: 'DROP', log: 1, log_limit: '1/min' } },
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		assert.match(contains('limit name "lan.log_limit"'), extractChain(renderWith(), 'drop_to_lan'));
	});

	it('log_limit without log declares the limit object but zone chains log nothing', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, input: 'DROP', log_limit: '3/min' } },
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		const nft = renderWith();
		assert.match(contains('limit lan.log_limit {'),       nft);
		assert.match(not(contains('limit name "lan.log_limit"')), extractChain(nft, 'drop_from_lan'));
	});

	it('log without log_limit emits inline log prefix in drop chains instead of a named limit', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, input: 'DROP', log: 1 } },
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		const drop = extractChain(renderWith(), 'drop_from_lan');
		assert.match(contains('log prefix'),           drop);
		assert.match(not(contains('limit name')),      drop);
	});

	it('masq + log_limit declares the limit and uses it in drop and accept chains', () => {
		mock.global.patch('uci', { data: {
			firewall: { '@zone[0]': { '.type': 'zone', name: 'wan', network: 'wan', auto_helper: 0,
			                         family: 'ipv4', masq: 1, output: 'ACCEPT', log: 1, log_limit: '2/min' } },
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': { interface: [
			{ interface: 'wan', up: true, l3_device: 'pppoe-wan', device: 'pppoe-wan',
			  'ipv4-address': [{ address: '10.11.12.1', mask: 24 }] }
		] } } });
		const nft = renderWith();
		assert.match(contains('limit wan.log_limit {'),                    nft);
		assert.match(contains('limit name "wan.log_limit"'), extractChain(nft, 'drop_from_wan'));
		// The ct state invalid guard inside accept_to_wan also gets a log+limit prefix
		assert.match(contains('limit name "wan.log_limit"'), extractChain(nft, 'accept_to_wan'));
	});

	it('rule with log: 1 targeting a zone with log_limit uses the zone named limit', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, input: 'DROP', log: 1, log_limit: '1/min' },
				'@rule[0]': { '.type': 'rule', proto: 'tcp', dest: 'lan', dest_port: '1003', log: '1' }
			},
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		assert.match(contains('limit name "lan.log_limit"'), extractChain(renderWith(), 'output_lan'));
	});

	it('rule with log: 0 targeting a zone with log_limit emits no log prefix statement', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, input: 'DROP', log: 1, log_limit: '1/min' },
				'@rule[0]': { '.type': 'rule', proto: 'tcp', dest: 'lan', dest_port: '1004', log: '0' }
			},
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		const output_lan = extractChain(renderWith(), 'output_lan');
		assert.match(truthy(), output_lan !== null);
		assert.match(not(contains('log prefix')), output_lan);
	});

	it('rule with log: 1 sourced from a zone with log_limit uses the source zone named limit', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, input: 'DROP', log: 1, log_limit: '1/min' },
				'@rule[0]': { '.type': 'rule', proto: 'tcp', src: 'lan', dest_port: '1001', log: '1' }
			},
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		assert.match(contains('limit name "lan.log_limit"'), extractChain(renderWith(), 'input_lan'));
	});

	it('rule with src: * and dest: zone uses the dest zone log_limit in the forward chain', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, input: 'DROP', log: 1, log_limit: '1/min' },
				'@rule[0]': { '.type': 'rule', proto: 'tcp', src: '*', dest: 'lan', dest_port: '1005', log: '1' }
			},
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		assert.match(contains('limit name "lan.log_limit"'), extractChain(renderWith(), 'forward'));
	});

	it('rule with src: * and no dest zone reference gets an inline log — no named limit', () => {
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]': { '.type': 'zone', name: 'lan', network: 'lan', auto_helper: 0, input: 'DROP', log: 1, log_limit: '1/min' },
				'@rule[0]': { '.type': 'rule', proto: 'tcp', src: '*', dest_port: '1007', log: '1' }
			},
			helpers: {}
		}});
		mock.global.patch('ubus', { data: { 'network.interface:dump': IFACES } });
		const input = extractChain(renderWith(), 'input');
		assert.match(contains('log prefix'),           input);
		assert.match(not(contains('limit name')),      input);
	});
});
