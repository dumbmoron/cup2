// Copyright (C) 2025 imput
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

import { CupError, type CupTicket } from './lib/util.ts';
import { CupParticipant } from './participant.ts';
import * as Bytes from './lib/bytes.ts';
import * as ECDSA from './lib/ecdsa.ts';

export class CupClient extends CupParticipant {
    #key_id: number;

    constructor(key_id: number, key: CryptoKey) {
        if (key.type !== 'public') {
            throw `invalid key type: ${key.type}, must be 'public'`;
        }

        if (!key.usages.includes('verify')) {
            throw `key usages do not include 'verify'`;
        }

        super({ [key_id]: key });
        this.#key_id = key_id;
    }

    /**
     * Takes a request and adds all the necessary CUP stuff to it
     * as preparation for sendoff. Pass in `request` before its
     * body is consumed. The request is cloned by the method, you
     * do not need to clone it yourself.
     * @param request Request with unconsumed body. Cloned by the
     *                function, you don't need to clone it yourself.
     * @param nonce An optional nonce override for testing. Do not set
     *              this in production unless you have a better PRNG
     *              than what is offered by `crypto.getRandomValues()`.
     * @returns An object containing the modified Request, as well as a ticket
     *          for use when verifying the response.
     */
    async wrap(request: Request, nonce?: string): Promise<{ request: Request; ticket: CupTicket }> {
        const url = new URL(request.url);
        const nonce_ = nonce || crypto.getRandomValues(new Uint32Array(1))[0];

        url.searchParams.set('cup2key', `${this.#key_id}:${nonce_}`);

        const ticket = await this.makeTicket(new Request(url, request));
        url.searchParams.set('cup2hreq', Bytes.toHex(ticket.hash));

        return {
            request: new Request(url, request),
            ticket,
        };
    }

    /**
     * Takes the server response and verifies that it was correctly
     * signed by the expected ECDSA key, throws if the response is
     * not valid.
     * @param response Response with unconsumed body. Cloned by the
     *                function, you don't need to clone it yourself.
     * @param ticket Ticket made by the wrap() call.
     * @returns Nothing.
     */
    async verify(response: Response, ticket: CupTicket): Promise<void> {
        const key = this.keys[ticket.keyId]!;

        let proof = response.headers.get('X-Cup-Server-Proof');
        if (!proof) {
            const etag = response.headers.get('ETag');
            if (etag && etag.startsWith('W/"') && etag.endsWith('"')) {
                proof = etag.substring(3, etag.length - 1);
            } else if (etag) {
                proof = etag;
            }
        }

        if (!proof) {
            throw new CupError('proof is missing in response or invalid');
        }

        const [sig_, hash_] = proof.split(':');
        if (!sig_ || hash_?.length !== 64) {
            throw new CupError('signature or hash is missing from proof or invalid');
        }

        const sig = ECDSA.toRs(Bytes.fromHex(sig_));
        const hash = Bytes.fromHex(hash_);

        if (!Bytes.bufEq(hash, ticket.hash)) {
            throw new CupError('hash mismatch in response proof');
        }

        const data = await this.makeProofData(response, ticket);
        const valid = await crypto.subtle.verify(
            { name: 'ECDSA', hash: 'SHA-256' },
            key,
            sig,
            data,
        );

        if (!valid) {
            throw new CupError('signature is invalid');
        }
    }
}
