package org.tinywind.service;

import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.PropertyNamingStrategies;
import tools.jackson.databind.json.JsonMapper;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;
import org.tinywind.model.IdToken;
import org.tinywind.model.KeycloakToken;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.Map;

/**
 * @author tinywind
 */
@Service
public class KeycloakService {
    private static final Log log = LogFactory.getLog(KeycloakService.class);

    private static final String KEYCLOAK_DOMAIN;
    private static final String KEYCLOAK_REALM;
    private static final String KEYCLOAK_CLIENT_SECRET;
    private static final String KEYCLOAK_OPENID_SUB_URI = "/protocol/openid-connect/";

    public static final String SERVICE_DOMAIN;
    public static final String KEYCLOAK_CLIENT_ID;
    public static final String KEYCLOAK_AUTH_URL;
    public static final String KEYCLOAK_TOKEN_URL;
    public static final String KEYCLOAK_USERINFO_URL;
    public static final String KEYCLOAK_LOGOUT_URL;

    static {
        SERVICE_DOMAIN = System.getProperty("service.domain");
        URI provider = URI.create(System.getProperty("keycloak.domain"));
        if (!"https".equalsIgnoreCase(provider.getScheme()) || provider.getHost() == null
                || provider.getUserInfo() != null || provider.getQuery() != null || provider.getFragment() != null) {
            throw new IllegalArgumentException("keycloak.domain must be an HTTPS URL without credentials, query or fragment");
        }
        KEYCLOAK_DOMAIN = provider.toString().replaceAll("/+$", "") + "/realms/";
        KEYCLOAK_REALM = System.getProperty("keycloak.realm");
        KEYCLOAK_CLIENT_ID = System.getProperty("keycloak.client.id");
        KEYCLOAK_CLIENT_SECRET = System.getProperty("keycloak.client.secret");

        KEYCLOAK_AUTH_URL = KEYCLOAK_DOMAIN + KEYCLOAK_REALM + KEYCLOAK_OPENID_SUB_URI + "auth";
        KEYCLOAK_TOKEN_URL = KEYCLOAK_DOMAIN + KEYCLOAK_REALM + KEYCLOAK_OPENID_SUB_URI + "token";
        KEYCLOAK_USERINFO_URL = KEYCLOAK_DOMAIN + KEYCLOAK_REALM + KEYCLOAK_OPENID_SUB_URI + "userinfo";
        KEYCLOAK_LOGOUT_URL = KEYCLOAK_DOMAIN + KEYCLOAK_REALM + KEYCLOAK_OPENID_SUB_URI + "logout";
    }

    public KeycloakToken getToken(String code) throws IOException {
        final MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set("grant_type", "authorization_code");
        parameters.set("client_id", KEYCLOAK_CLIENT_ID);
        parameters.set("client_secret", KEYCLOAK_CLIENT_SECRET);
        parameters.set("code", code);
        parameters.set("redirect_uri", SERVICE_DOMAIN + "/login");

        RestTemplate restTemplate = new RestTemplate();
        String response = restTemplate.postForObject(KEYCLOAK_TOKEN_URL, parameters, String.class);

        ObjectMapper mapper = JsonMapper.builder()
                .configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_PROPERTIES, false)
                .propertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
                .build();
        KeycloakToken token = mapper.readValue(response, KeycloakToken.class);

        for (String s : token.getIdToken().split("[.]")) {
            try {
                String decoded = new String(Base64.getDecoder().decode(s));
                IdToken idToken = mapper.readValue(decoded, IdToken.class);
                token.setId(idToken);
            } catch (Exception ignored) {
            }
        }

        return token;
    }

    public Map getUserInfo(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);

        RestTemplate restTemplate = new RestTemplate();
        HttpEntity<String> entity = new HttpEntity<>(headers);
        HttpEntity<Map> response = restTemplate.exchange(KEYCLOAK_USERINFO_URL, HttpMethod.GET, entity, Map.class);

        return response.getBody();
    }
}
