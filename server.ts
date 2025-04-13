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

import type { CupTicket } from './lib/util.ts';
import { CupParticipant } from './participant.ts';
import * as Bytes from './lib/bytes.ts';
import * as ECDSA from './lib/ecdsa.ts';

export class CupServer extends CupParticipant {
    constructor(keys: Record<number, CryptoKey>) {
        for (const key of Object.values(keys)) {
            if (key.type !== 'private') {
                throw `invalid key type: ${key.type}, must be 'private'`;
            }

            if (!key.usages.includes('sign')) {
                throw `key usages do not include 'sign'`;
            }
        }

        super(keys);
    }

    /**
     * Creates a ticket from the request body, which is used
     * for later response signature.
     * @param request Request with unconsumed body. Cloned by the
     *                function, you don't need to clone it yourself.
     * @returns An opaque ticket representing the data needed to sign
     *          the response.
    **/
    override makeTicket(request: Request): Promise<CupTicket> {
        return super.makeTicket(request);
    }

    /**
     * Takes the server response and modifies it so that
     * it includes the server-signed CUP response in its
     * headers.
     * @param response Response to sign.
     * @param ticket Ticket made by the makeTicket() call.
     * @param [write_etag=false] Whether to write the CUP signature
     *        also into the ETag header. This is off by default because
     *        it's a hack, only enable it if you are certain you need it.
     * @returns Response containing CUP headers with the
     *          signature.
    **/
    async sign(response: Response, ticket: CupTicket, write_etag = false): Promise<Response> {
        // We know this key exists, because we validated it
        // in makeTicket(), and we know it's valid because
        // we validated the contents in the constructor.
        const key = this.keys[ticket.keyId]!;

        const proofBytes = await crypto.subtle.sign(
            { name: 'ECDSA', hash: 'SHA-256' },
            key,
            await this.makeProofData(response, ticket),
        );

        const proof = `${
            Bytes.toHex(
                ECDSA.fromRs(new Uint8Array(proofBytes)),
            )
        }:${Bytes.toHex(ticket.hash)}`;

        response.headers.set('X-Cup-Server-Proof', proof);

        // This part of the protocol is kinda a hack.
        // Let's not do this unless we really need to.
        if (write_etag) {
            response.headers.set('ETag', `W/"${proof}"`);
        }

        return response;
    }
}
