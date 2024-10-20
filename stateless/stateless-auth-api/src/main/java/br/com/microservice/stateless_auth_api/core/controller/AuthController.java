package br.com.microservice.stateless_auth_api.core.controller;

import br.com.microservice.stateless_auth_api.core.dto.AuthRequest;
import br.com.microservice.stateless_auth_api.core.dto.TokenDTO;
import br.com.microservice.stateless_auth_api.core.service.AuthService;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.*;

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
    public TokenDTO login(@RequestHeader String acessToken){
        return authService.validateToken(acessToken);
    }

}
