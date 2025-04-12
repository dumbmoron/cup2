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

import * as Bytes from './bytes.ts';
import { char } from './util.ts';

const INTEGER_TAG = 0x02;
const SEQUENCE_TAG = 0x30;

function* read_asn1_ints(data: Uint8Array): Generator<Uint8Array> {
    if (!data.length) {
        return;
    }

    const [tag, len] = data;
    if (tag !== INTEGER_TAG) {
        throw 'expected an INTEGER';
    }

    yield data.slice(2, len + 2);
    yield* read_asn1_ints(data.slice(len + 2));
}

function read_asn1(asn1: Uint8Array) {
    const [tag, len] = asn1;
    if (tag !== SEQUENCE_TAG) {
        throw 'expected ASN.1 sequence';
    }

    return read_asn1_ints(asn1.slice(2, len + 2));
}

export function toRs(asn1: Uint8Array) {
    const [r, s, _] = read_asn1(asn1);
    if (_) {
        throw 'too many integers';
    }

    const rs_len = Math.round((r.length + s.length) / 16) * 16;
    const rs = new Uint8Array(rs_len);
    let offset = 0;

    for (let v of [r, s]) {
        if (!v[0] && v.length % 16 === 1) {
            v = v.slice(1);
        } else if (v.length % 16 === 15) {
            v = new Uint8Array(Bytes.toBytes('\0', v));
        }

        rs.set(v, offset);
        offset += v.length;
    }

    return rs;
}

export function fromRs(rs_: Uint8Array): Uint8Array {
    const rs = new Uint8Array(rs_);
    const paramSize = rs.length / 2;

    return Bytes.toBytes(
        char(SEQUENCE_TAG),
        String.fromCharCode(rs.length + 2 + 2),
        char(INTEGER_TAG),
        String.fromCharCode(paramSize),
        rs.slice(0, paramSize),
        char(INTEGER_TAG),
        String.fromCharCode(paramSize),
        rs.slice(paramSize),
    );
}
