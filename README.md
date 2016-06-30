# DockerAuthentication
Docker token authentication service implementation in php

This is a php implementation of Docker Registry v2 authentication via central service.

As described by docker here:

<https://docs.docker.com/registry/spec/auth/token/>

and the JWT spec:

<https://docs.docker.com/registry/spec/auth/jwt/>

Rough implementation outline

1. Create a config.yml with the fields listed in config.yaml.dist.
2. Create your docker registry plus configuration of a proxy if you wish to have a port in the URL.
3. Update your docker registry config.yml, example listed below.
4. Restart your registry after changes to the registries config.yaml.

This is the docker run command I use to initialze my registry I use port 50000 with a apache proxy setup for that port to be served on a subdomain.

```
docker run -d -it -p 50000:5000 --restart=always --name registry \
  -v /srv/docker_registry/data:/var/lib/registry \
  -v /srv/docker_registry/certs:/certs \
  -v /srv/docker_registry/config/config.yml:/etc/docker/registry/config.yml \
  registry:2
```
The certs folder contains my pem files for my cert and private key that I use for ssl on the subdomain I have set for my proxy, that way the alpine registry container can serve https

Notible it is also important that the certs volumn contain your full CA file (letsencrypt default names this file fullchain.pem)

I also overide the intire config.yml for the registry to give me full controll over its configuration instead of using ENV params in the docke run.

This is my config.yaml, you will have to fill out the placeholders to match your servers configuration.

Issuer must match your issuer that you specify in the config.yml for your authenticaiton service.

The registry configuration docs can be found here:

<https://docs.docker.com/registry/configuration/>

```
version: 0.1
log:
  fields:
    service: registry
storage:
    cache:
        blobdescriptor: inmemory
    filesystem:
        rootdirectory: /var/lib/registry
http:
    addr: :5000
    secret: gE6045DNMfWzicuBJ3ol
    tls:
        certificate: /certs/cert.pem
        key: /certs/privkey.pem
    headers:
        X-Content-Type-Options: [nosniff]
auth:
    token:
        realm: https://myAuthService.com/docker/v2/token
        service: myDockerRegistry.com
        issuer: myAuthService.com
        rootcertbundle: /certs/fullchain.pem
health:
  storagedriver:
    enabled: true
    interval: 10s
    threshold: 3
```
