package br.com.microservice.stateful_auth_api.core.service;

import br.com.microservice.stateful_auth_api.core.dto.TokenData;
import br.com.microservice.stateful_auth_api.core.infra.exception.AuthenticationException;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.ValidationException;
import lombok.AllArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class TokenService {

    private static final Long ONE_DAY_IN_SECONDS = 86400L;
    private static final Integer TOKEN_INDEX = 1;
    private static final String EMPTY = " ";

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    public String createToken(String username){
        var acessToken = UUID.randomUUID().toString();
        var data = new TokenData(username);
        var jsonData = getJsonData(data);
        redisTemplate.opsForValue().set(acessToken, jsonData, ONE_DAY_IN_SECONDS);
        redisTemplate.expireAt(acessToken, Instant.now().plusSeconds(ONE_DAY_IN_SECONDS));
        return acessToken;
    }

    private String getJsonData(Object payload){

        try{
            return objectMapper.writeValueAsString(payload);
        }catch (Exception e){
            throw new AuthenticationException("Error to parse object to json");
        }
    }

    public TokenData getTokenData(String token){
        var acessToken = extractToken(token);

        var jsonString = getRedisTokenValue(acessToken);

        try {
            return objectMapper.readValue(jsonString, TokenData.class);
        } catch (JsonProcessingException e) {
            throw new ValidationException("Error to parse json to object");
        }

    }

    private String getRedisTokenValue(String token){
        return redisTemplate.opsForValue().get(extractToken(token));
    }

    public boolean validateAcessToken(String token){
        var acessToken = extractToken(token);
        var data = getRedisTokenValue(acessToken);
        return !isEmpty(data);
    }

    public void deleteToken(String token){
        var acessToken = extractToken(token);
        redisTemplate.delete(acessToken);
    }

    private String extractToken(String token){
        if(isEmpty(token)){
            throw new ValidationException("The acess token was not informed");
        }

        if(token.contains(EMPTY)){
            return token.split(EMPTY)[TOKEN_INDEX];
        }
        return token;
    }
}
