# DockerAuthentication
*A simple PAM-based Docker token authentication service implemented in PHP*

This is a straightforward, lightweight implementation of central-service Docker Registry v2 authentication as described in the Docker docs (<https://docs.docker.com/registry/spec/auth/token/>) and the JWT spec (<https://docs.docker.com/registry/spec/auth/jwt/>).
The service uses PAM as its underlying authentication system, but it would be trivial to modify/extend the code to support any sort of username/password based authentication, included something custom.

## Setup

1. Download/unpack the source to the location you will host it from. If you are using Apache, you can host this as is (because we've included an appropriate .htaccess). If you are using another web server, you will (currently) need to handle routing all sub-URLs to "index.php" via your web server's URL rewriting mechanism. If your web server has .htaccess disabled, you will need to bring the URL rewriting instructions into your central configuration file.
1. Configure the service by creating a config.yml based on the "config.yaml.dist" example file. The auth service must have access to a valid TLS certificate and private key
2. Spin up a docker registry container if you haven't already, see the Docker documentation for details on this step.
3. Update your registry's config.yml to include the "auth" section as detailed in the example below. 
4. Restart your registry container to make your configuration changes active.

### Configuring the auth service
```
private_key: "path/to/private/key/privkey.pem"
issuer: "myAuthService.com"
audience: "myDockerRegistry.com"
#optionally
blacklisted_users : ["userNameYouDoNotWantToGiveRegistryAccess"]
```
The private key given must be the one used for the certificate that you provide to the "rootcertbundle" registry option described below.
The issuer and audience can be anything as long as your registry and your auth service agree, but it is recommended that they be based on DNS. The "issuer" represents your authentication service and the "audience" represents your registry. 

### Spin up a docker registry

Here is an example command to start a Docker registry container. Here we use port 50000 so that we can proxy it with mod_proxy (not shown here) and serve it on port 443 along with other services. If you want to run the registry standalone (ie without a proxy) or via a different port, modify the publish-port (-p) argument as needed. 

```
docker run -d -it -p 50000:5000 --restart=always --name registry \
  -v /srv/docker_registry/data:/var/lib/registry \
  -v /srv/docker_registry/certs:/certs \
  -v /srv/docker_registry/config/config.yml:/etc/docker/registry/config.yml \
  registry:2
```
The certs volume contains the PEM-formatted certificate and its private key. This is standard for a Docker registry to be served over HTTPS (required). If you've read the documentation on private Docker registries, you should have already obtained a suitable TLS certificate for that. This is convenient if you wish to use  the same certificate to sign authentication tokens as you use to serve the registry's HTTPS. If you wish to use a different certificate, you will need to provide the certificate-chain (ie fullchain) version of that certificate in addition to the certificate you are using to serve. If you are using LetsEncrypt, the certificate-chain file is provided as "fullchain.pem" within your live certificates store (/etc/letsencrypt/live/example.com/fullchain.pem)

### Configure your Docker registry 

Adjust your registry configuration to use the auth service:

```
auth:
    token:
        realm: https://myAuthService.com/docker/v2/token
        service: myDockerRegistry.com
        issuer: myAuthService.com
        rootcertbundle: /certs/fullchain.pem
```

Obviously, you will need to enter your own values for realm, service, issuer, and rootcertbundle.
 * "realm" is the fully-qualified URL where your auth service is installed. Note that the "docker/v2/token" part of the URL is provided by this authentication service.
 * The "issuer" string must match the one that you specify in the auth service's config.yml
 * The "service" string here must match the "audience" string in the auth service's config.yml
 * The "rootcertbundle" must be the cert+intermediates chain which may be provided by your certificate authority, or can be constructed from your certificate and the appropriate intermediate certificates as described elsewhere.

In our case, we prefer to override the registry's entire config.yml for full control over its configuration (as opposed to using environment variables). See the Docker registry documentation (<https://docs.docker.com/registry/configuration/>) for more information about how to configure using environment variables.

For your convenience, here is a complete docker registry config.yml (IMPORTANT: make sure to generate your own secret for the "secret" parameter).

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
    secret: MYSECRETKEYHERE
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

If you already have a config.yml for your registry, you do not need to change all your settings to match the above. The critical section is the "auth" section.


