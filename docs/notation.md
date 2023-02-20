# Container Image Sign and Verify with notation tool

| :zap: Requirement | nerdctl >= 1.3.0 |
|-------------------|------------------|

[notation](https://github.com/notaryproject/notation) is a project to add signatures as standard items in the registry ecosystem, and to build a set of simple tooling for signing and verifying these signatures.

You can enable container signing and verifying features with `push` and `pull` commands of `nerdctl` by using `notation`
under the hood with make use of flags `--sign` while pushing the container image, and `--verify` while pulling the
container image.

> * Ensure notation executable in your `$PATH`.
> * You can install notation by following this page: https://notaryproject.dev/docs/installation/cli/

Prepare your environment:

```shell
# Create a sample Dockerfile
$ cat <<EOF | tee Dockerfile.dummy
FROM alpine:latest
CMD [ "echo", "Hello World" ]
EOF
```

> Please do not forget, we won't be validating the base images, which is `alpine:latest` in this case, of the container image that was built on,
> we'll only verify the container image itself once we sign it.

```shell

# Build the image
$ nerdctl build -t devopps/hello-world -f Dockerfile.dummy .

# Generate a key-pair in notation's key store and trust store
$ notation cert generate-test --default "test"

# Confirm the signing key is correctly configured. Key name with a * prefix is the default key.
$ notation key ls

# Confirm the certificate is stored in the trust store.
$ notation cert ls
```

Sign the container image while pushing:

```
# Sign the image and store the signature in the registry
$ nerdctl push --sign=notation --notation-key-name test devopps/hello-world
```

Verify the container image while pulling:

> REMINDER: Image won't be pulled if there are no matching signatures in case you passed `--verify` flag.

```shell
# Create the trust policy under $XDG_CONFIG_HOME/notation
{
    "version": "1.0",
    "trustPolicies": [
        {
            "name": "test-images",
            "registryScopes": [ "*" ],
            "signatureVerification": {
                "level" : "strict"
            },
            "trustStores": [ "ca:test.io" ],
            "trustedIdentities": [
                "*"
            ]
        }
    ]
}

# Verify the image
$ nerdctl pull --verify=notation devopps/hello-world

# You can not verify the image if it is not signed by the cert in the trust policy
$ nerdctl pull --verify=notation devopps/hello-world-bad
```
