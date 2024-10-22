package br.com.microservice.stateful_auth_api.core.controller;

import br.com.microservice.stateful_auth_api.core.dto.AuthRequest;
import br.com.microservice.stateful_auth_api.core.dto.AuthUserResponse;
import br.com.microservice.stateful_auth_api.core.dto.TokenDTO;
import br.com.microservice.stateful_auth_api.core.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;

@RestController
@AllArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    public TokenDTO login(@RequestBody AuthRequest Request){
        return authService.login(Request);
    }

    @PostMapping("/token/validate")
    public TokenDTO validateToken(@RequestHeader String acessToken){
        return authService.validateToken(acessToken);
    }

    @PostMapping("/logout")
    public HashMap<String,Object> logout(@RequestHeader String acessToken){
        authService.logout(acessToken);
        var response = new HashMap<String,Object>();
        var ok = HttpStatus.OK;

        response.put("status", ok.name());
        response.put("code", ok.value());

        return response;
    }

    @GetMapping("/user")
    public AuthUserResponse getAuthenticatedUser(@RequestHeader String acessToken){
        return authService.getAuthenticatedUser(acessToken);
    }

}
