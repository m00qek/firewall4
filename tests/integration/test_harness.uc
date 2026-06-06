'use strict';

// Shared helpers for integration tests that render the full nftables ruleset.

const _render = render;

// extract_chain(ruleset, name) — return the body of a named chain, or null if absent.
// When using not() matchers, first assert the chain exists with:
//   assert.match(truthy(), chain !== null);
// to avoid vacuous passes when a regression removes the chain entirely.
function extractChain(ruleset, name) {
	let lines = split(ruleset, '\n');
	let result = [], inChain = false;
	for (let line in lines) {
		if (!inChain) {
			if (line == `\tchain ${name} {`) inChain = true;
		} else {
			if (line == '\t}') break;
			push(result, line);
		}
	}
	return inChain ? join('\n', result) : null;
}

// Absolute path to the ruleset template.  The Docker test environment mounts the
// repo at /app (see Makefile), and sourcedir() is unavailable in require()'d modules
// in this ucode version, so the path is hardcoded to the Docker mount point.
const TEMPLATE = '/app/root/usr/share/firewall4/templates/ruleset.uc';

// makeRenderWith(fw4) — return a renderWith() closure bound to the given fw4 instance.
function makeRenderWith(fw4) {
	return function() {
		fw4.state = null;
		fw4.load(false);
		const nft = _render(TEMPLATE, { fw4, type, exists, length });
		fw4.state = null;
		return nft;
	};
}

return { extractChain, makeRenderWith };
