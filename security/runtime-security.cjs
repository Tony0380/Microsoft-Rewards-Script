'use strict'

// CVE-2026-111497: use the Node release floor, not process.versions.brotli.
const minimums = Object.freeze({ 22: [23, 4], 24: [22, 1], 26: [12, 1] })

function isPatchedNode(version) {
    const match = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(String(version))
    if (!match) return false
    const [, major, minor, patch] = match.map(Number)
    const floor = minimums[major]
    return Boolean(floor && (minor > floor[0] || (minor === floor[0] && patch >= floor[1])))
}

function assertRuntime(version = process.versions.node) {
    if (!isPatchedNode(version)) {
        throw new Error(
            'CVE-2026-111497: unsupported or vulnerable Node.js ' +
                version +
                '. Require 22.23.4+, 24.22.1+, or 26.12.1+ within these supported release lines.'
        )
    }
}

async function regression() {
    const assert = require('node:assert/strict')
    const zlib = require('node:zlib')
    const input = Buffer.from('200010414141fcffff07002228f00b60f7f41f000000', 'hex')
    assert.throws(
        () => zlib.brotliDecompressSync(input, { maxOutputLength: 32 * 1024 * 1024 }),
        error => error.errno === -17
    )
    const ordinary = Buffer.from('Brotli legitimate input '.repeat(128))
    assert.deepEqual(zlib.brotliDecompressSync(zlib.brotliCompressSync(ordinary)), ordinary)
    await new Promise((resolve, reject) => {
        const decoder = zlib.createBrotliDecompress()
        decoder.resume()
        decoder.once('error', error => (error.errno === -17 ? resolve() : reject(error)))
        decoder.once('end', () => reject(new Error('Invalid Brotli block switch was accepted')))
        for (const byte of input) decoder.write(Buffer.from([byte]))
        decoder.end()
    })
}

assertRuntime()
module.exports = { isPatchedNode, assertRuntime, regression }
if (typeof module !== 'undefined' && module.parent === null) {
    const check = process.argv.includes('--regression') ? regression() : Promise.resolve()
    check
        .then(() => console.log('Runtime security gate passed: Node ' + process.versions.node))
        .catch(error => {
            console.error(error.message)
            process.exitCode = 1
        })
}
