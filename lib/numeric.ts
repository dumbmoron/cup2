export const toNumber = (input: unknown, base = 10) => {
    if (typeof input !== 'string') {
        throw 'invalid input';
    }

    const num = parseInt(input, base);
    if (isNaN(num) || num.toString(base).padStart(2, '0') !== input.padStart(2, '0')) {
        throw 'number is invalid';
    }

    return num;
};

export const toBigInt = (input: unknown) => {
    if (typeof input !== 'string') {
        throw 'invalid input';
    }

    const num = BigInt(input);
    if (num.toString() !== input) {
        throw 'number is invalid';
    }

    return num;
};
