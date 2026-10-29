package org.tinywind;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.boot.SpringApplication;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

public class LauncherSecurityTest {
    private static final AtomicInteger providerRequests = new AtomicInteger();
    private static final AtomicInteger untrustedRequests = new AtomicInteger();
    private static final SSLSocketFactory originalFactory = HttpsURLConnection.getDefaultSSLSocketFactory();
    private static final HostnameVerifier originalVerifier = HttpsURLConnection.getDefaultHostnameVerifier();
    private static HttpsServer provider;
    private static HttpsServer untrusted;
    private static ConfigurableApplicationContext application;
    private static String base;

    @BeforeClass
    public static void startIsolatedServers() throws Exception {
        Path temporary = Files.createTempDirectory(Paths.get(System.getProperty("java.io.tmpdir")), "keycloak-tls-");
        KeyStore trustedStore = certificate(temporary.resolve("trusted.p12"));
        provider = server(trustedStore, providerRequests);
        untrusted = server(certificate(temporary.resolve("untrusted.p12")), untrustedRequests);
        TrustManagerFactory trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(trustedStore);
        SSLContext trustedContext = SSLContext.getInstance("TLS");
        trustedContext.init(null, trust.getTrustManagers(), new SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(trustedContext.getSocketFactory());
        System.setProperty("service.domain", "http://127.0.0.1:8080");
        System.setProperty("keycloak.domain", "https://localhost:" + provider.getAddress().getPort());
        System.setProperty("keycloak.realm", "fixture");
        System.setProperty("keycloak.client.id", "fixture-client");
        System.setProperty("keycloak.client.secret", "fixture-only");
        SpringApplication spring = new SpringApplication(Launcher.class);
        Map<String, Object> properties = new HashMap<>();
        properties.put("server.port", "0");
        properties.put("server.address", "127.0.0.1");
        spring.setDefaultProperties(properties);
        application = spring.run("--server.port=0", "--server.address=127.0.0.1");
        base = "http://127.0.0.1:" + application.getEnvironment().getProperty("local.server.port");
    }

    @AfterClass
    public static void stopIsolatedServers() {
        if (application != null) application.close();
        if (provider != null) provider.stop(0);
        if (untrusted != null) untrusted.stop(0);
        HttpsURLConnection.setDefaultSSLSocketFactory(originalFactory);
        HttpsURLConnection.setDefaultHostnameVerifier(originalVerifier);
        for (String key : new String[]{"service.domain", "keycloak.domain", "keycloak.realm", "keycloak.client.id", "keycloak.client.secret"}) System.clearProperty(key);
    }

    @Test
    public void rejectsUntrustedCertificatesBeforeSendingHttp() {
        int before = untrustedRequests.get();
        assertThrows(ResourceAccessException.class, () -> new RestTemplate().getForObject(
                "https://localhost:" + untrusted.getAddress().getPort() + "/health", String.class));
        assertEquals(before, untrustedRequests.get());
    }

    @Test
    public void privateCaRetainsHostnameVerification() {
        RestTemplate client = new RestTemplate();
        assertEquals("fixture-ok", client.getForObject("https://localhost:" + provider.getAddress().getPort() + "/health", String.class));
        assertThrows(ResourceAccessException.class, () -> client.getForObject(
                "https://127.0.0.1:" + provider.getAddress().getPort() + "/health", String.class));
    }

    @Test
    public void loginStateIsUnpredictableAndBoundToItsSession() throws Exception {
        Response first = request("/", null);
        String firstState = state(first);
        assertTrue(firstState.matches("[A-Za-z0-9_-]{43}"));
        Response second = request("/", null);
        assertNotEquals(firstState, state(second));
        int before = providerRequests.get();
        assertEquals(400, request("/login?code=fixture-code&state=" + firstState, second.cookie).status);
        assertEquals(before, providerRequests.get());
    }

    @Test
    public void invalidStateIsRejectedBeforeAnyProviderRequest() throws Exception {
        Response page = request("/", null);
        int before = providerRequests.get();
        assertEquals(400, request("/login?code=fixture-code&state=wrong", page.cookie).status);
        assertEquals(400, request("/login?code=fixture-code", page.cookie).status);
        assertEquals(before, providerRequests.get());
    }

    @Test
    public void validCallbackDisplaysUserInfoAndCannotBeReplayed() throws Exception {
        Response page = request("/", null);
        String callback = "/login?code=fixture-code&state=" + state(page);
        Response loggedIn = request(callback, page.cookie);
        assertEquals(loggedIn.body, 200, loggedIn.status);
        assertTrue(loggedIn.body.contains("fixture-user"));
        int before = providerRequests.get();
        assertEquals(400, request(callback, page.cookie).status);
        assertEquals(before, providerRequests.get());
        assertEquals(200, request("/user-info", page.cookie).status);
    }

    @Test
    public void userInfoRequiresAnAuthenticatedSession() throws Exception {
        int before = providerRequests.get();
        assertEquals(401, request("/user-info?token=fixture-token", null).status);
        assertEquals(before, providerRequests.get());
    }

    private static String state(Response page) {
        assertEquals(page.body, 200, page.status);
        Matcher matcher = Pattern.compile("[?&](?:amp;)?state=([^&\"'<>]+)").matcher(page.body);
        assertTrue(page.body, matcher.find());
        return matcher.group(1);
    }

    private static Response request(String path, String cookie) throws Exception {
        HttpURLConnection connection = (HttpURLConnection) new URL(base + path).openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);
        if (cookie != null) connection.setRequestProperty("Cookie", cookie);
        try {
            int status = connection.getResponseCode();
            String setCookie = connection.getHeaderField("Set-Cookie");
            try (InputStream stream = status >= 400 ? connection.getErrorStream() : connection.getInputStream()) {
                return new Response(status, stream == null ? "" : new String(read(stream), StandardCharsets.UTF_8),
                        setCookie == null ? cookie : setCookie.split(";", 2)[0]);
            }
        } finally {
            connection.disconnect();
        }
    }

    private static HttpsServer server(KeyStore store, AtomicInteger requests) throws Exception {
        KeyManagerFactory keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, "fixture-only".toCharArray());
        SSLContext context = SSLContext.getInstance("TLS");
        context.init(keys.getKeyManagers(), null, new SecureRandom());
        HttpsServer server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        server.createContext("/", exchange -> {
            requests.incrementAndGet();
            String path = exchange.getRequestURI().getPath();
            String body = "fixture-ok";
            if (path.endsWith("/token")) {
                String form = new String(read(exchange.getRequestBody()), StandardCharsets.UTF_8);
                if (!form.contains("grant_type=authorization_code") || !form.contains("client_id=fixture-client")) {
                    exchange.sendResponseHeaders(400, -1);
                    exchange.close();
                    return;
                }
                String id = Base64.getUrlEncoder().withoutPadding().encodeToString("{\"sub\":\"fixture-user\",\"preferred_username\":\"fixture-user\"}".getBytes(StandardCharsets.UTF_8));
                body = "{\"access_token\":\"fixture-token\",\"id_token\":\"e30." + id + ".fixture\"}";
                exchange.getResponseHeaders().set("Content-Type", "application/json");
            } else if (path.endsWith("/userinfo")) {
                body = "{\"preferred_username\":\"fixture-user\"}";
                exchange.getResponseHeaders().set("Content-Type", "application/json");
            }
            byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(200, bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.close();
        });
        server.start();
        return server;
    }

    private static KeyStore certificate(Path path) throws Exception {
        Process process = new ProcessBuilder(Paths.get(System.getProperty("java.home"), "bin", "keytool").toString(),
                "-genkeypair", "-alias", "fixture", "-keystore", path.toString(), "-storetype", "PKCS12",
                "-storepass", "fixture-only", "-keypass", "fixture-only", "-keyalg", "RSA", "-keysize", "2048",
                "-validity", "1", "-dname", "CN=localhost", "-ext", "SAN=dns:localhost", "-noprompt")
                .redirectErrorStream(true).start();
        byte[] output = read(process.getInputStream());
        assertEquals(new String(output, StandardCharsets.UTF_8), 0, process.waitFor());
        KeyStore store = KeyStore.getInstance("PKCS12");
        try (InputStream stream = Files.newInputStream(path)) { store.load(stream, "fixture-only".toCharArray()); }
        return store;
    }

    private static byte[] read(InputStream input) throws java.io.IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        byte[] buffer = new byte[4096];
        int length;
        while ((length = input.read(buffer)) != -1) output.write(buffer, 0, length);
        return output.toByteArray();
    }

    private static class Response {
        final int status;
        final String body;
        final String cookie;
        Response(int status, String body, String cookie) { this.status = status; this.body = body; this.cookie = cookie; }
    }
}
