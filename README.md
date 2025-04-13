# @imput/cup2

Client/server implementation of the
[Chromium/Omaha CUP-ECDSA protocol](https://github.com/google/omaha/blob/c0fcf45e4c46ddf2e1e7972f4405fb4ec7b4d079/doc/ClientUpdateProtocolEcdsa.md)
in Typescript.

## Examples

### client
```ts
import { CupClient } from '@imput/cup2';

const keyId = /* your key ID goes here */;
const keyBytes = new Uint8Array([
    /* your EC pubkey bytes go here, or you can load it from a file */
]);

// This is the side of the requestor of resources,
// which is usually a browser reaching out to some API.
const publicKey = await crypto.subtle.importKey(
    'spki', keyBytes,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false, ['verify'],
);

const client = new CupClient(keyId, publicKey);

const raw_request = new Request('http://clients2.google.com/time/1/current');
const { request, ticket } = await client.wrap(raw_request);

// make the request after adding cup parameters
const response = await fetch(request);

// verify() throws a CupError if the signature is not valid
await client.verify(response, ticket);

// we can now consume the response
console.log(await response.text());
```

### server
```ts
import { CupServer } from '@imput/cup2';

const keys: Record<number, CryptoKey> = {
    /* keys should be periodically rotated,
       but we still need to support older
       clients. this is why you are able to
       insert multiple keys here. load them
       from a file or something, this is entirely
       up to you
    */
};

const cup = new CupServer(keys);

Deno.serve(async (request: Request) => {
    // this library assumes all your incoming requests use CUP.
    // if this is not the case, you need to check for presence
    // of cup2key in request.url.searchParams and decide whether
    // you want to use CUP or not

    // this is separated from the signing process
    // so that we can do some preliminary checks and not
    // waste processing time if the request does not meet the
    // preconditions.
    const ticket = await cup.makeTicket(request);
    // hold on to this ticket, do some work ...
    // ...
    // we have a response!
    const response = new Response();
    // sign and return
    // TODO: cup.* methods throw a CupError if something
    // is wrong -- you probably want to check for that.
    return cup.sign(response, ticket);
});
```

more:

- [mod_test.ts](mod_test.ts)
- [client_test.ts](client_test.ts)

## License

AGPL-3.0, see [LICENSE](LICENSE).

For other licensing options, you can reach us at meow [@] imput.net.
