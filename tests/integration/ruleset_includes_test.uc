'use strict';

// nftables include statement placement and include section filtering.
//
// Out of scope: ACTION=includes code path (tests/06_includes/03_script_includes).
// That path reads /var/run/fw4.state and calls system() to execute script-type
// includes — it requires a real statefile and shell environment that the render
// harness does not provide.  It is tested by the shell test runner only.

import { describe, it, assert, truthy, contains, not, afterEach, mock } from 'utest';

// ── Global module setup ─────────────────────────────────────────────────────

const _h = require('test_harness');
const extractChain = _h.extractChain;

const KERNEL   = 'Linux version 5.4.101 (build) #0 SMP Tue Mar 2 14:41:54 2021\n';
const NFT_JSON = '{"nftables":[{"metainfo":{"json_schema_version":1}}]}';
const BASE_FILES    = { '/proc/version': KERNEL, '/sys/class/net/eth0/flags': '0x1003', '/sys/class/net/eth1/flags': '0x1003' };
const BASE_COMMANDS = { '/usr/sbin/nft --terse --json list flowtables inet': NFT_JSON };

// extra_behavior is spread after the builtins, allowing callers to supply glob/lsdir overrides.
// readlink always returns null — mocked include files are never symlinks.
function fs_patch(extra_data, extra_behavior) {
	const data = { ...BASE_FILES, ...(extra_data ?? {}) };
	return {
		strict:   true,
		behavior: {
			readfile: function(path) {
				if (exists(data, path)) return data[path];
				if (match(path, /^\/sys\/class\/net\/.+\/flags$/)) return '0x1003';
				die("strict mock: 'fs.readfile' called with unmocked path: " + path);
			},
			readlink: () => null,
			...(extra_behavior ?? {})
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

describe('includes — nftables include positions', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.patch('fs', fs_patch()); });

	const ZONE = { '@zone[0]': { '.type': 'zone', name: 'test', device: ['eth0'], auto_helper: 0 } };

	it('ruleset-pre places the include before the table declaration', () => {
		mock.global.patch('fs', fs_patch({ '/etc/pre.nft': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				...ZONE,
				'@include[0]': { '.type': 'include', path: '/etc/pre.nft', type: 'nftables', position: 'ruleset-pre' }
			},
			helpers: {}
		}});
		const before_table = split(renderWith(), 'table inet fw4 {')[0];
		assert.match(contains('include "/etc/pre.nft"'), before_table);
	});

	it('ruleset-post places the include after the table closing brace', () => {
		mock.global.patch('fs', fs_patch({ '/etc/post.nft': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				...ZONE,
				'@include[0]': { '.type': 'include', path: '/etc/post.nft', type: 'nftables', position: 'ruleset-post' }
			},
			helpers: {}
		}});
		const after_table = split(renderWith(), '\n}\n')[1];
		assert.match(contains('include "/etc/post.nft"'), after_table);
	});

	it('table-pre places the include inside the table before the first chain', () => {
		mock.global.patch('fs', fs_patch({ '/etc/table-pre.nft': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				...ZONE,
				'@include[0]': { '.type': 'include', path: '/etc/table-pre.nft', type: 'nftables', position: 'table-pre' }
			},
			helpers: {}
		}});
		const inside_table       = split(renderWith(), 'table inet fw4 {')[1];
		const before_first_chain = split(inside_table, '\tchain ')[0];
		assert.match(contains('include "/etc/table-pre.nft"'), before_first_chain);
	});

	it('table-post (default) places the include inside the table after the last chain', () => {
		mock.global.patch('fs', fs_patch({ '/etc/table-post.nft': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				...ZONE,
				'@include[0]': { '.type': 'include', path: '/etc/table-post.nft', type: 'nftables' }
			},
			helpers: {}
		}});
		const nft        = renderWith();
		const pos_inc    = index(nft, 'include "/etc/table-post.nft"');
		const pos_end    = index(nft, '\n}\n');
		// The include is inside the table (before the closing brace)...
		assert.match(truthy(), pos_inc > 0 && pos_inc < pos_end);
		// ...and no chain definition follows it within the table.
		assert.match(not(contains('\tchain ')), substr(nft, pos_inc, pos_end - pos_inc));
	});

	it('chain-pre places the include before the first rule in the named chain', () => {
		mock.global.patch('fs', fs_patch({ '/etc/chain-pre.nft': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				...ZONE,
				'@include[0]': { '.type': 'include', path: '/etc/chain-pre.nft', type: 'nftables',
				                 position: 'chain-pre', chain: 'forward' }
			},
			helpers: {}
		}});
		const forward = extractChain(renderWith(), 'forward');
		const inc_pos = index(forward, 'include "/etc/chain-pre.nft"');
		assert.match(truthy(), inc_pos >= 0);
		assert.match(truthy(), inc_pos < index(forward, 'ct state vmap'));
	});

	it('chain-post places the include after the last rule in the named chain', () => {
		mock.global.patch('fs', fs_patch({ '/etc/chain-post.nft': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				...ZONE,
				'@include[0]': { '.type': 'include', path: '/etc/chain-post.nft', type: 'nftables',
				                 position: 'chain-post', chain: 'forward' }
			},
			helpers: {}
		}});
		const forward = extractChain(renderWith(), 'forward');
		assert.match(truthy(),
			index(forward, 'include "/etc/chain-post.nft"') > index(forward, 'ct state vmap'));
	});

	it('chain-pre/post without a chain option is skipped', () => {
		mock.global.patch('fs', fs_patch({ '/etc/bad.nft': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				...ZONE,
				'@include[0]': { '.type': 'include', path: '/etc/bad.nft', type: 'nftables', position: 'chain-post' }
			},
			helpers: {}
		}});
		assert.match(not(contains('/etc/bad.nft')), renderWith());
	});
});

describe('includes — firewall.user compatibility', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.patch('fs', fs_patch()); });

	it('/etc/firewall.user without fw4_compatible is not rendered and emits a compatibility warning', () => {
		const warnings = [];
		mock.global.patch('fs', fs_patch({ '/etc/firewall.user': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]':    { '.type': 'zone', name: 'test', device: ['eth0'], auto_helper: 0 },
				'@include[0]': { '.type': 'include', path: '/etc/firewall.user' }
			},
			helpers: {}
		}});
		mock.inject_builtin('warn', (...args) => push(warnings, join('', args)), () => {
			assert.match(not(contains('/etc/firewall.user')), renderWith());
		});
		const warning_text = join('\n', warnings);
		assert.match(contains('not marked as compatible with fw4'), warning_text);
		assert.match(contains("requires 'option fw4_compatible 1'"), warning_text);
	});

	it('/etc/firewall.user with fw4_compatible: 1 is accepted as a script include (not rendered)', () => {
		mock.global.patch('fs', fs_patch({ '/etc/firewall.user': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]':    { '.type': 'zone', name: 'test', device: ['eth0'], auto_helper: 0 },
				'@include[0]': { '.type': 'include', path: '/etc/firewall.user', fw4_compatible: 1 }
			},
			helpers: {}
		}});
		assert.match(not(contains('/etc/firewall.user')), renderWith());
	});

	it('non-firewall.user script includes are auto-compatible and do not appear in rendered output', () => {
		mock.global.patch('fs', fs_patch({ '/usr/share/miniupnpd/firewall.include': '' }));
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]':    { '.type': 'zone', name: 'test', device: ['eth0'], auto_helper: 0 },
				'@include[0]': { '.type': 'include', path: '/usr/share/miniupnpd/firewall.include' }
			},
			helpers: {}
		}});
		assert.match(not(contains('/usr/share/miniupnpd/firewall.include')), renderWith());
	});
});

describe('includes — enabled flag', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.patch('fs', fs_patch()); });

	it('enabled: 0 suppresses the include', () => {
		mock.global.patch('fs', fs_patch({
			'/etc/yes.nft':  '',
			'/etc/yes2.nft': '',
			'/etc/no.nft':   ''
		}));
		mock.global.patch('uci', { data: {
			firewall: {
				'@zone[0]':    { '.type': 'zone', name: 'test', device: ['eth0'], auto_helper: 0 },
				'@include[0]': { '.type': 'include', path: '/etc/yes.nft',  type: 'nftables' },
				'@include[1]': { '.type': 'include', path: '/etc/yes2.nft', type: 'nftables', enabled: '1' },
				'@include[2]': { '.type': 'include', path: '/etc/no.nft',   type: 'nftables', enabled: '0' }
			},
			helpers: {}
		}});
		const nft = renderWith();
		assert.match(contains('/etc/yes.nft'),     nft);
		assert.match(contains('/etc/yes2.nft'),    nft);
		assert.match(not(contains('/etc/no.nft')), nft);
	});
});

describe('includes — automatic /usr/share/nftables.d/ scanning', () => {
	afterEach(() => { mock.global.unpatch('uci'); mock.global.patch('fs', fs_patch()); });

	const ZONE_UCI = { data: {
		firewall: { '@zone[0]': { '.type': 'zone', name: 'test', device: ['eth0'], auto_helper: 0 } },
		helpers: {}
	}};

	it('nft files in /usr/share/nftables.d/table-post/ are auto-included after all chains', () => {
		// fw4 calls fs.access(path) on each glob result before including it
		mock.global.patch('fs', fs_patch(
			{ '/usr/share/nftables.d/table-post/auto.nft': '' },
			{
				glob:  (pat) => pat == '/usr/share/nftables.d/table-post/*.nft'
				                ? ['/usr/share/nftables.d/table-post/auto.nft'] : [],
				lsdir: () => null
			}
		));
		mock.global.patch('uci', ZONE_UCI);
		const nft     = renderWith();
		const pos_inc = index(nft, 'include "/usr/share/nftables.d/table-post/auto.nft"');
		const pos_end = index(nft, '\n}\n');
		assert.match(truthy(), pos_inc > 0 && pos_inc < pos_end);
		assert.match(not(contains('\tchain ')), substr(nft, pos_inc, pos_end - pos_inc));
	});

	it('nft files in /usr/share/nftables.d/ruleset-pre/ are auto-included before the table declaration', () => {
		mock.global.patch('fs', fs_patch(
			{ '/usr/share/nftables.d/ruleset-pre/pre.nft': '' },
			{
				glob:  (pat) => pat == '/usr/share/nftables.d/ruleset-pre/*.nft'
				                ? ['/usr/share/nftables.d/ruleset-pre/pre.nft'] : [],
				lsdir: () => null
			}
		));
		mock.global.patch('uci', ZONE_UCI);
		const before_table = split(renderWith(), 'table inet fw4 {')[0];
		assert.match(contains('include "/usr/share/nftables.d/ruleset-pre/pre.nft"'), before_table);
	});

	it('nft files in /usr/share/nftables.d/ruleset-post/ are auto-included after the table closing brace', () => {
		mock.global.patch('fs', fs_patch(
			{ '/usr/share/nftables.d/ruleset-post/post.nft': '' },
			{
				glob:  (pat) => pat == '/usr/share/nftables.d/ruleset-post/*.nft'
				                ? ['/usr/share/nftables.d/ruleset-post/post.nft'] : [],
				lsdir: () => null
			}
		));
		mock.global.patch('uci', ZONE_UCI);
		const after_table = split(renderWith(), '\n}\n')[1];
		assert.match(contains('include "/usr/share/nftables.d/ruleset-post/post.nft"'), after_table);
	});

	it('nft files in /usr/share/nftables.d/chain-pre/<chain>/ are auto-included at the start of the named chain', () => {
		// lsdir returns the chain subdirectory names; fw4 then globs each one for .nft files
		mock.global.patch('fs', fs_patch(
			{ '/usr/share/nftables.d/chain-pre/forward/auto.nft': '' },
			{
				glob:  (pat) => pat == '/usr/share/nftables.d/chain-pre/forward/*.nft'
				                ? ['/usr/share/nftables.d/chain-pre/forward/auto.nft'] : [],
				lsdir: (path) => path == '/usr/share/nftables.d/chain-pre' ? ['forward'] : null
			}
		));
		mock.global.patch('uci', ZONE_UCI);
		const forward = extractChain(renderWith(), 'forward');
		assert.match(truthy(), forward !== null);
		const inc_pos = index(forward, 'include "/usr/share/nftables.d/chain-pre/forward/auto.nft"');
		assert.match(truthy(), inc_pos >= 0);
		assert.match(truthy(), inc_pos < index(forward, 'ct state vmap'));
	});

	it('nft files in /usr/share/nftables.d/chain-post/<chain>/ are auto-included at the end of the named chain', () => {
		mock.global.patch('fs', fs_patch(
			{ '/usr/share/nftables.d/chain-post/forward/auto.nft': '' },
			{
				glob:  (pat) => pat == '/usr/share/nftables.d/chain-post/forward/*.nft'
				                ? ['/usr/share/nftables.d/chain-post/forward/auto.nft'] : [],
				lsdir: (path) => path == '/usr/share/nftables.d/chain-post' ? ['forward'] : null
			}
		));
		mock.global.patch('uci', ZONE_UCI);
		const forward = extractChain(renderWith(), 'forward');
		assert.match(truthy(), forward !== null);
		assert.match(truthy(),
			index(forward, 'include "/usr/share/nftables.d/chain-post/forward/auto.nft"') >
			index(forward, 'ct state vmap'));
	});
});
