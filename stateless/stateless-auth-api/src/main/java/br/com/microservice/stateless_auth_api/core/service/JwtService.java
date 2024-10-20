package br.com.microservice.stateless_auth_api.core.service;
import br.com.microservice.stateless_auth_api.core.model.User;
import br.com.microservice.stateless_auth_api.infra.exception.AuthenticationException;
import br.com.microservice.stateless_auth_api.infra.exception.ValidationException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;
import java.util.HashMap;
import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@RequiredArgsConstructor
public class JwtService {

    private static final Integer ONE_DAY_IN_HOURS = 24;
    private static final Integer TOKEN_INDEX = 1;
    private static final String EMPTY = " ";


    @Value("${app.token.secret-key}")
    private String secretKey;

    public String createToken(User user){
        var data = new HashMap<String, String>();
        data.put("id", user.getId().toString());
        data.put("username", user.getUsername());
        return Jwts.builder().setClaims(data).setExpiration(generateExpiresAt()).signWith(generateSign()).compact();
    }

    private Date generateExpiresAt(){
        return Date.from(LocalDateTime.now().plusHours(ONE_DAY_IN_HOURS)
                .atZone(ZoneId.systemDefault()).toInstant());
    }

    private SecretKey generateSign(){
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    public void validateAccessToken(String token) {
        String accessToken = extractToken(token);

        try {
            SecretKey key = generateSign();

            JwtParser parser = Jwts.parser()
                    .setSigningKey(key)
                    .build();

            parser.parseClaimsJws(accessToken); // Validação do token

        } catch (Exception ex) {
            throw new AuthenticationException("Invalid access token: " + ex.getMessage());
        }
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
