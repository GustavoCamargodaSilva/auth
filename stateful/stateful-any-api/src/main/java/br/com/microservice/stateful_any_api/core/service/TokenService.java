package br.com.microservice.stateful_any_api.core.service;

import br.com.microservice.stateful_any_api.core.client.TokenClient;
import br.com.microservice.stateful_any_api.core.dto.AuthUserResponse;
import br.com.microservice.stateful_any_api.infra.exception.AuthenticationException;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
@Slf4j
public class TokenService {

    private final TokenClient tokenClient;

    public void validateToken(String acessToken) {

        try {
            log.info("Validating token {} ", acessToken);

            var response = tokenClient.validateToken(acessToken);

            log.info("Token {} is valid", response.accessToken());

        } catch (Exception ex) {

            throw new AuthenticationException("Authentication error");

        }
    }

    public AuthUserResponse getAuthenticatedUser(String acessToken) {
        try {
            log.info("Getting authenticated user with token {} ", acessToken);

            var response =  tokenClient.getAuthenticatedUser(acessToken);

            log.info("Authenticated user {} ", response.toString());

            return response;

        }catch (Exception ex) {

            throw new AuthenticationException("Auth to get authenticated user");

        }
    }



}
