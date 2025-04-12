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

import { CupError, type CupTicket, sha256 } from './lib/util.ts';
import * as Numeric from './lib/numeric.ts';
import * as Bytes from './lib/bytes.ts';

export class CupParticipant {
    protected keys: Record<number, CryptoKey>;

    constructor(keys: Record<number, CryptoKey>) {
        for (const key of Object.values(keys)) {
            if (key.algorithm.name !== 'ECDSA') {
                throw `invalid key algo: ${key.algorithm}, must be ECDSA`;
            }
        }

        this.keys = keys;
    }

    protected async makeTicket(request: Request): Promise<CupTicket> {
        const url = new URL(request.url);
        const cup2key = url.searchParams.get('cup2key');
        const cup2hreq = url.searchParams.get('cup2hreq');

        if (cup2key === null) {
            throw new CupError('cup2key value is missing');
        }

        const [keyId, nonce] = cup2key.split(':');

        if (!keyId || !nonce) {
            throw new CupError('cup2key value is invalid');
        }

        if (!(Numeric.toNumber(keyId) in this.keys)) {
            throw new CupError('requested cup key does not exist');
        }

        const hash = await sha256(await request.clone().bytes());

        if (cup2hreq && !Bytes.bufEq(Bytes.fromHex(cup2hreq), hash)) {
            throw new CupError('cup2hreq does not match local hash');
        }

        return {
            hash,
            keyId: Numeric.toNumber(keyId),
            nonce,
        };
    }

    protected async makeProofData(response: Response, ticket: CupTicket): Promise<Uint8Array> {
        const request_hash = ticket.hash;
        const response_hash = await sha256(await response.clone().bytes());
        const cup2key_query = `${ticket.keyId}:${ticket.nonce}`;

        return sha256(Bytes.toBytes(request_hash, response_hash, cup2key_query));
    }
}
