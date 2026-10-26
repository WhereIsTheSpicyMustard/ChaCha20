My implementation of the ChaCha20 stream cipher.  This implementation does not include the
Poly1305 authentication algorithm, as I am primarily going to use this as a csprng.
Implementation details and test vectors were taken from:

```
https://www.rfc-editor.org/info/rfc8439/
```
