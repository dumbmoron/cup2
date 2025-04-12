import { assertEquals } from '@std/assert';
import { CupClient, CupServer } from './mod.ts';

Deno.test(async function end_to_end() {
    for (let keyId = 0; keyId < 256; ++keyId) {
        const { publicKey, privateKey } = await crypto.subtle.generateKey(
            { name: 'ECDSA', namedCurve: 'P-256' },
            false,
            ['sign', 'verify'],
        );

        const client = new CupClient(keyId, publicKey);
        const server = new CupServer({ [keyId]: privateKey });

        const { request, ticket } = await client.wrap(
            new Request('http://clients2.google.com/time/1/current'),
        );

        const s_ticket = await server.makeTicket(request);
        assertEquals(ticket.hash, s_ticket.hash);
        assertEquals(ticket.keyId, s_ticket.keyId);
        assertEquals(ticket.nonce, s_ticket.nonce);
        assertEquals(ticket, s_ticket);

        const response = await server.sign(new Response('poop'), s_ticket);

        await client.verify(response, ticket);
    }
});
