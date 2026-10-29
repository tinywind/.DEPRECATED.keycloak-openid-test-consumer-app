#!/usr/bin/env bash

mvn compile exec:java \ 
        -Dfile.encoding=utf-8 \
        -Dservice.domain=http://localhost:8000 \
        -Dkeycloak.domain=https://{keycloak hostname}/auth \
        -Dkeycloak.realm={realm} \
        -Dkeycloak.client.id={client id} \
        -Dkeycloak.client.secret={client secret} \
        [-Dexec.args="--server.port={http listening port}"]
