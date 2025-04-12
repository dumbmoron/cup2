export class CupError extends Error {}

export type CupTicket = {
    hash: Uint8Array;
    keyId: number;
    nonce: string;
};

export const char = (n: number) => String.fromCharCode(n);
export const sha256 = async (input: Uint8Array) => {
    return new Uint8Array(
        await crypto.subtle.digest('SHA-256', input),
    );
};
