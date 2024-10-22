package br.com.microservice.stateless_any_api.core.service;

import br.com.microservice.stateless_any_api.core.dto.AnyResponse;
import lombok.AllArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class AnyService {

    private final JwtService jwtService;


    public AnyResponse getData(String acessToken) {

        jwtService.validateAcessToken(acessToken);
        var authUser = jwtService.getAuthenticatedUser(acessToken);
        var ok = HttpStatus.OK;
        return new AnyResponse(ok.name(), ok.value(), authUser);
    }
}
