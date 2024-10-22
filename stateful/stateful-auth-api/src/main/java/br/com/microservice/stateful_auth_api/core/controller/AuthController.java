package br.com.microservice.stateful_auth_api.core.controller;
import br.com.microservice.stateful_auth_api.core.dto.AuthRequest;
import br.com.microservice.stateful_auth_api.core.dto.AuthUserResponse;
import br.com.microservice.stateful_auth_api.core.dto.TokenDTO;
import br.com.microservice.stateful_auth_api.core.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@RestController
@AllArgsConstructor
@RequestMapping("api/auth")
public class AuthController {

    private final AuthService service;

    @PostMapping("login")
    public TokenDTO login(@RequestBody AuthRequest request) {
        return service.login(request);
    }

    @PostMapping("token/validate")
    public TokenDTO validateToken(@RequestHeader String accessToken) {
        return service.validateToken(accessToken);
    }

    @PostMapping("logout")
    public HashMap<String, Object> logout(@RequestHeader String accessToken) {
        service.logout(accessToken);
        var response = new HashMap<String, Object>();
        response.put("status", "OK");
        response.put("code", 200);
        return response;
    }

    @GetMapping("user")
    public AuthUserResponse getAuthenticatedUser(@RequestHeader String accessToken) {
        return service.getAuthenticatedUser(accessToken);
    }

}
