package org.tinywind.controller;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;
import org.tinywind.model.KeycloakToken;
import org.tinywind.service.KeycloakService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;

import static org.tinywind.service.KeycloakService.*;

/**
 * @author tinywind
 */
@Controller
public class MainController {

    private static final Log log = LogFactory.getLog(MainController.class);
    private static final SecureRandom RANDOM = new SecureRandom();

    @Autowired
    private KeycloakService service;

    @RequestMapping("")
    public String mainPage(HttpServletRequest request, HttpSession session, Model model) throws UnsupportedEncodingException {
        String redirectUri = ("/" + request.getContextPath() + "/login").replaceAll("//", "/");

        byte[] randomState = new byte[32];
        RANDOM.nextBytes(randomState);
        String state = Base64.getUrlEncoder().withoutPadding().encodeToString(randomState);
        session.setAttribute("state", state);
        model.addAttribute("state", state);
        model.addAttribute("clientId", KEYCLOAK_CLIENT_ID);
        model.addAttribute("redirectUri", URLEncoder.encode(SERVICE_DOMAIN + redirectUri, "utf-8"));
        model.addAttribute("authUrl", KEYCLOAK_AUTH_URL);
        return "main";
    }

    @RequestMapping("login")
    public String loginPage(HttpSession session, Model model,
                            @RequestParam(value = "code", required = false) String code,
                            @RequestParam(value = "state", required = false) String state) throws IOException {
        synchronized (session) {
            Object expected = session.getAttribute("state");
            if (!(expected instanceof String) || state == null || code == null || code.isBlank()
                    || !MessageDigest.isEqual(((String) expected).getBytes(StandardCharsets.UTF_8), state.getBytes(StandardCharsets.UTF_8))) {
                throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid login callback");
            }
            session.removeAttribute("state");
        }
        KeycloakToken token = service.getToken(code);
        final String accessToken = token.getAccessToken();
        Map userInfo = service.getUserInfo(accessToken);
        session.setAttribute("accessToken", accessToken);
        model.addAttribute("accessToken", accessToken);
        model.addAttribute("code", code);
        model.addAttribute("state", state);
        model.addAttribute("sessionState", state);
        model.addAttribute("userInfo", userInfo);
        model.addAttribute("token", token);

        return "user-info";
    }

    @RequestMapping("user-info")
    public String userInfoPage(Model model, HttpSession session) throws IOException {
        String token = (String) session.getAttribute("accessToken");
        if (token == null) throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Login required");
        model.addAttribute("userInfo", service.getUserInfo(token));

        return "user-info";
    }

    @RequestMapping("**")
    @ResponseBody
    public Map<String, String[]> anyPage(HttpServletRequest request) {
        return request.getParameterMap();
    }
}
