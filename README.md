# keycloak-openid-test-consumer-app

# How to Play: Method 1
* Install Maven 3 and JDK 17.
* Run `mvn verify` for the seven real HTTP/TLS tests and executable JAR.
* run command: 
```
mvn compile exec:java \ 
        -Dfile.encoding=utf-8 \
        -Dservice.domain=http://localhost:8000 \
        -Dkeycloak.domain=https://{keycloak hostname}/auth \
        -Dkeycloak.realm={realm} \
        -Dkeycloak.client.id={client id} \
        -Dkeycloak.client.secret={client secret} \
        [-Dexec.args="--server.port={http listening port}"]
```

The provider URL requires HTTPS. Certificate chains and hostnames use the normal JVM verification rules. For a private CA, import its certificate into a dedicated truststore and supply `-Djavax.net.ssl.trustStore=/path/to/truststore.p12` and `-Djavax.net.ssl.trustStorePassword=...` before `-jar` or through Maven's JVM options. Keep hostname verification enabled.

After `mvn verify`, run `java` with the same `-Dservice.domain` and `-Dkeycloak.*` properties followed by `-jar target/keycloak-openid-test-consumer-app-0.1.jar`. A localhost HTTP callback is supported; configure its exact `/login` redirect URI in Keycloak.

Each login state contains 256 random bits, belongs to its HTTP session, and is consumed before the token exchange. Invalid callbacks return HTTP 400 without contacting the provider. `/user-info` uses the access token stored by a valid callback and requires that session. The existing token and user-info views remain diagnostic displays.

Tests generate their own certificates, run real loopback HTTPS providers and HTTP callbacks, and verify certificate rejection, hostname checks, session binding, replay rejection and startup rejection of HTTP providers. They do not contact a live Keycloak instance.

# LICENSE
**Licensed under the MIT**
