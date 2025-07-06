# Links

## Skopeo

Skopeo is a command line utility that performs various operations on container images and image repositories. It can copy container images between registries, delete images from remote registries, and inspect images without pulling them locally.

<https://github.com/containers/skopeo>



```shell
podman pull docker.io/bitnami/postgresql:latest
podman tag docker.io/bitnami/postgresql:latest localhost:5000/postgresql:latest
podman push localhost:5000/postgresql:latest
```



```shell
docker run --rm --name cilium bitnami/cilium:latest cilium-dbg version

```
## Bitnami Premium

Features and Benefits should be analyzed in the context of the Bitnami Premium offering, which provides a curated set of applications and development stacks that are optimized for security and performance.

[Bitnami Premium](https://www.arrow.com/globalecs/na/vendors/bitnami-premium/)

## Bitnami Free

[Bitname Free](https://github.com/bitnami/containers)

## Notation

Standards-based spec and tooling for securing software supply chains
Signing and verifying artifacts. Safeguarding the software delivery security from development to deployment.

[Notation](https://notaryproject.dev/)

```shell
docker run -d -p 5001:5000 -e REGISTRY_STORAGE_DELETE_ENABLED=true --name registry registry
docker build -t localhost:5001/net-monitor:v1 https://github.com/wabbit-networks/net-monitor.git#main
docker push localhost:5001/net-monitor:v1

```

```shell
docker inspect --format='{{index .RepoDigests 0}}' localhost:5001/net-monitor:v1

```

```shell
localhost:5001/net-monitor@sha256:2df36634ca0685910e290d251644a6dea07215e9eb52953fa3efd776be57aa9a
```

```shell

IMAGE=localhost:5001/net-monitor@sha256:2df36634ca0685910e290d251644a6dea07215e9eb52953fa3efd776be57aa9a
notation ls $IMAGE
localhost:5001/net-monitor@sha256:2df36634ca0685910e290d251644a6dea07215e9eb52953fa3efd776be57aa9a has no associated signature
➜  ~ notation cert generate-test --default "wabbit-networks.io"

generating RSA Key with 2048 bits
generated certificate expiring on 2025-06-11T13:10:59Z
wrote key: /Users/bulent/Library/Application Support/notation/localkeys/wabbit-networks.io.key
wrote certificate: /Users/bulent/Library/Application Support/notation/localkeys/wabbit-networks.io.crt
Successfully added wabbit-networks.io.crt to named store wabbit-networks.io of type ca
wabbit-networks.io: added to the key list
wabbit-networks.io: mark as default signing key
➜  ~ notation key ls

NAME                   KEY PATH                                                                              CERTIFICATE PATH                                                                      ID   PLUGIN NAME
* wabbit-networks.io   /Users/bulent/Library/Application Support/notation/localkeys/wabbit-networks.io.key   /Users/bulent/Library/Application Support/notation/localkeys/wabbit-networks.io.crt
➜  ~ notation cert ls
STORE TYPE   STORE NAME           CERTIFICATE
ca           wabbit-networks.io   wabbit-networks.io.crt
➜  ~ notation sign $IMAGE

Successfully signed localhost:5001/net-monitor@sha256:2df36634ca0685910e290d251644a6dea07215e9eb52953fa3efd776be57aa9a
➜  ~ notation sign --signature-format cose $IMAGE

Successfully signed localhost:5001/net-monitor@sha256:2df36634ca0685910e290d251644a6dea07215e9eb52953fa3efd776be57aa9a
➜  ~ notation ls $IMAGE
localhost:5001/net-monitor@sha256:2df36634ca0685910e290d251644a6dea07215e9eb52953fa3efd776be57aa9a
└── application/vnd.cncf.notary.signature
    ├── sha256:8a5cedeedd1dfdd434f290a811c780cccf2d2dbc7360a1e4bd0f21f9a7fb8074
    └── sha256:dd80b3517e706b50ad1013b6c6070af8cbda816aac68b0a9bf91cde238bc7101

```

```json
cat <<EOF > ./trustpolicy.json
{
    "version": "1.0",
    "trustPolicies": [
        {
            "name": "wabbit-networks-images",
            "registryScopes": [ "*" ],
            "signatureVerification": {
                "level" : "strict"
            },
            "trustStores": [ "ca:wabbit-networks.io" ],
            "trustedIdentities": [
                "*"
            ]
        }
    ]
}
EOF

```



```shell
notation policy import ./trustpolicy.json
notation verify $IMAGE

```