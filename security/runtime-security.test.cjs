'use strict'
const { test } = require('node:test')
const assert = require('node:assert/strict')
const { spawnSync } = require('node:child_process')
const path = require('node:path')
const { isPatchedNode, assertRuntime, regression } = require('./runtime-security.cjs')

test('rejects vulnerable, EOL, odd, unknown and prerelease runtimes', () => {
    for (const version of [
        '18.20.8',
        '20.20.2',
        '21.9.0',
        '22.23.3',
        '22.22.99',
        '23.11.0',
        '24.22.0',
        '24.21.99',
        '25.9.0',
        '26.12.0',
        '26.11.99',
        '28.0.0',
        '24.22.1-rc.1',
        '24',
        'invalid',
        ''
    ]) {
        assert.equal(isPatchedNode(version), false, version)
        assert.throws(() => assertRuntime(version), /CVE-2026-111497/)
    }
})
test('accepts each patched boundary and later patches in supported lines', () => {
    for (const version of ['22.23.4', '22.23.5', '22.24.0', '24.22.1', '24.23.0', '26.12.1', '26.13.0', 'v24.22.1']) {
        assert.equal(isPatchedNode(version), true, version)
        assert.doesNotThrow(() => assertRuntime(version))
    }
})
test('preload covers direct node entrypoints', () => {
    const result = spawnSync(
        process.execPath,
        [
            '--require',
            path.join(__dirname, 'runtime-security.cjs'),
            '-e',
            'process.stdout.write("application-started")'
        ],
        { encoding: 'utf8', timeout: 10000 }
    )
    assert.equal(result.status, 0, result.stderr)
    assert.equal(result.stdout, 'application-started')
})
test('rejects malformed Brotli synchronously and in chunks while preserving normal input', regression)
