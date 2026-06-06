'use strict';

import { describe, it, assert, equals, mock } from 'utest';

// Establish a global fs proxy before requiring fw4 so that fw4's module-level
// require("fs") receives the proxy. Each test then controls fs behaviour via
// mock.inject(), which pushes a temporary layer read by the already-bound proxy.
mock.global.patch('fs', {});

const fw4 = require('fw4');

function mock_proc_version(content) {
	return {
		behavior: {
			open: (path) => path == '/proc/version' ? {
				read: () => content,
				close: () => null
			} : null
		}
	};
}

describe('fw4.read_kernel_version', () => {
	// Regression b6e5157 ("fw4: fix reading kernel version"):
	//   Old code: regex required a patch number, so "6.12" returned 0.
	//   Old code: patch was shifted left by 8 bits — 5.15.107 gave 0x050F6B00 (wrong).
	//   New code: patch is optional and encoded in the lowest byte without a shift.

	it('encodes patch in the lowest byte — regression b6e5157 (old code shifted by 8, giving 0x050F6B00)', () => {
		mock.inject('fs', mock_proc_version('Linux version 5.15.107-1-generic (build info)\n'), () => {
			// (5 << 24) | (15 << 16) | 107 = 0x050F006B
			assert.match(equals(0x050F006B), fw4.read_kernel_version());
		});
	});

	it('handles a version string without a patch number — regression b6e5157 (old regex required patch)', () => {
		mock.inject('fs', mock_proc_version('Linux version 6.12\n'), () => {
			// (6 << 24) | (12 << 16) | 0 = 0x060C0000
			assert.match(equals(0x060C0000), fw4.read_kernel_version());
		});
	});

	it('parses a 6.1.x version string', () => {
		mock.inject('fs', mock_proc_version('Linux version 6.1.38\n'), () => {
			// (6 << 24) | (1 << 16) | 38 = 0x06010026
			assert.match(equals(0x06010026), fw4.read_kernel_version());
		});
	});

	it('returns 0 when /proc/version cannot be opened', () => {
		mock.inject('fs', { behavior: { open: () => null } }, () => {
			assert.match(equals(0), fw4.read_kernel_version());
		});
	});

	it('returns 0 when /proc/version does not start with "Linux version"', () => {
		mock.inject('fs', mock_proc_version('Darwin Kernel Version 23.0.0\n'), () => {
			assert.match(equals(0), fw4.read_kernel_version());
		});
	});
});
