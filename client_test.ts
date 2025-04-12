import { assertEquals } from '@std/assert';
import { CupClient } from './mod.ts';
import * as Bytes from './lib/bytes.ts';
import { sha256 } from './lib/util.ts';

// Example blobs taken from: https://github.com/chromium/chromium/commit/fc52255e49e81da5d46a3dad4c103db89ee19e12
Deno.test(async function wrap_and_verify() {
    const keyId = 9;
    const keyBytes = new Uint8Array([
        0x30,
        0x59,
        0x30,
        0x13,
        0x06,
        0x07,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x02,
        0x01,
        0x06,
        0x08,
        0x2A,
        0x86,
        0x48,
        0xCE,
        0x3D,
        0x03,
        0x01,
        0x07,
        0x03,
        0x42,
        0x00,
        0x04,
        0x51,
        0x8B,
        0x06,
        0x03,
        0x4D,
        0xEA,
        0x13,
        0xC3,
        0x32,
        0x9B,
        0x15,
        0x73,
        0xD6,
        0xBC,
        0x47,
        0x33,
        0x3F,
        0xB6,
        0x95,
        0x0E,
        0x5D,
        0x52,
        0x73,
        0x70,
        0x5D,
        0xE4,
        0x92,
        0xBD,
        0xFD,
        0xC5,
        0xB9,
        0xC6,
        0x51,
        0x81,
        0x2D,
        0x8B,
        0x46,
        0xC4,
        0x4C,
        0xB0,
        0xA5,
        0xC6,
        0xDB,
        0x5B,
        0xE4,
        0xDB,
        0x80,
        0x57,
        0x6B,
        0x4D,
        0x08,
        0x9C,
        0x3D,
        0x8B,
        0xC2,
        0xD9,
        0x27,
        0x9A,
        0xDE,
        0x3D,
        0xE2,
        0xCC,
        0x0A,
        0x20,
    ]);

    const key = await crypto.subtle.importKey(
        'spki',
        keyBytes,
        { name: 'ECDSA', namedCurve: 'P-256' },
        false,
        ['verify'],
    );

    const client = new CupClient(keyId, key);
    const nonce = 'poop';
    const emptyHash = await sha256(new Uint8Array());
    const hashHex = Bytes.toHex(emptyHash);

    const request_in = new Request('http://clients2.google.com/time/1/current');
    // do NOT pass `nonce` in production, simply let wrap() generate it for you.
    const { request, ticket } = await client.wrap(request_in, nonce);

    assertEquals(ticket.hash, emptyHash);
    assertEquals(hashHex, 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
    assertEquals(ticket.nonce, nonce);
    assertEquals(ticket.keyId, keyId);
    assertEquals(
        request.url,
        'http://clients2.google.com/time/1/current?cup2key=' + keyId + '%3A' + nonce +
            '&cup2hreq=' + hashHex,
    );

    const responses = [
        ')]}\'\n{"current_time_millis":1744495507991,"server_nonce":-3.8567293408964113E-284}',
        ')]}\'\n{"current_time_millis":1744498582442,"server_nonce":-3.1093906940750466E-207}',
        ')]}\'\n{"current_time_millis":1744498602759,"server_nonce":3.415298510133693E297}',
        ')]}\'\n{"current_time_millis":1744498612926,"server_nonce":-5.422625039450686E173}',
        ')]}\'\n{"current_time_millis":1744498618889,"server_nonce":-1.8348997423197083E-281}',
    ];

    const proofs = [
        '30450221009e17a90a363b547e276e0b3c2474d6a0a35c4c6dac81e1aa5cd5fbe554308220022056db1ce354486fe9ecdb14a5955bf7f315065ed4643cddc9e046afbf4750995d',
        '3045022100d86df32961d62dc93a195d73c28027956197f888fa68d857484e28bc7f7464cd02204cf449585869bf331e40e167f8db5761a567401f801fe80682ff6319564efd0b',
        '304602210091dd27d4384fd42eb08396e39f0593a76c585ffb3241d35a65785279752f9543022100b8abb02c3da245f4b6c1ce3adf42d5ce68038de192ca3644c5ba4003298c81bc',
        '30450220547dc1aa45475734a22bbb8515734c3df1fbac28c4137b0c83709def843c9ff5022100d48d37972595891502b8b2f3ee3295b02cfc4fb19c2468894c33d646583676ed',
        '3045022100ef693c7fa418445b814bbdde061e11777f437c29374d5926a93122c0767ff8b002205627c1796e52944dc99b3b411d987cb30d902ce8f70a76209fbf02243b04dbba',
    ];

    for (let i = 0; i < Math.max(responses.length, proofs.length); ++i) {
        const response = new Response(responses[i], {
            headers: { 'X-Cup-Server-Proof': `${proofs[i]}:${hashHex}` },
        });

        await client.verify(response, ticket);
    }
});
