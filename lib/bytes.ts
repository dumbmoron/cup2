import * as Numeric from './numeric.ts';

export const bufEq = (a: Uint8Array, b: Uint8Array) => {
    if (a.byteLength !== b.byteLength) {
        return false;
    }

    for (let i = 0; i < a.length; ++i) {
        if (a[i] !== b[i]) {
            return false;
        }
    }

    return true;
};

export const concatBytes = (...args: readonly Uint8Array[]): Uint8Array => {
    const out = new Uint8Array(
        args.map((a) => a.length)
            .reduce((a, b) => a + b),
    );
    let offset = 0;

    for (const arr of args) {
        out.set(arr, offset);
        offset += arr.byteLength;
    }

    return out;
};

const encoder = new TextEncoder();

export const toBytes = (...args: readonly (string | Uint8Array)[]): Uint8Array => {
    return concatBytes(
        ...args.map((arg) => {
            if (typeof arg === 'string') {
                arg = new Uint8Array(encoder.encode(arg));
            }

            return arg;
        }),
    );
};

export const fromHex = (input: unknown): Uint8Array => {
    if (Array.isArray(input)) {
        input = input.join('');
    }

    if (typeof input !== 'string' || input.length % 2 !== 0) {
        throw 'invalid hex input';
    }

    const output = new Uint8Array(input.length / 2);
    for (let i = 0; i < input.length; i += 2) {
        output[i / 2] = Numeric.toNumber(input[i] + input[i + 1], 16);
    }

    return output;
};

export const toHex = (input: Uint8Array): string => {
    const u8 = new Uint8Array(input);
    let out = '';

    for (const byte of u8) {
        out += byte.toString(16).padStart(2, '0');
    }

    return out;
};
