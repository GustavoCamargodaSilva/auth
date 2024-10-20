package br.com.microservice.stateless_auth_api.core.service;

import br.com.microservice.stateless_auth_api.core.dto.AuthRequest;
import br.com.microservice.stateless_auth_api.core.dto.TokenDTO;
import br.com.microservice.stateless_auth_api.core.repository.UserRepository;
import br.com.microservice.stateless_auth_api.infra.exception.ValidationException;
import lombok.AllArgsConstructor;
import org.antlr.v4.runtime.Token;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class AuthService {

    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final UserRepository userRepository;

    public TokenDTO login(AuthRequest request){
        var user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new ValidationException("User not found"));
        var acessToken = jwtService.createToken(user);
        validatePassword(request.password(), user.getPassword());
        return new TokenDTO(acessToken);
    }

    private void validatePassword(String rawPassword, String encodedPassword){
        if(isEmpty(rawPassword)){
            throw new ValidationException("Password must be informed");
        }
        if(!passwordEncoder.matches(rawPassword, encodedPassword)){
            throw new ValidationException("Invalid password");
        }
    }

    public TokenDTO validateToken(String acessToken){
        validateExistingToken(acessToken);
        jwtService.validateAccessToken(acessToken);
        return new TokenDTO(acessToken);
    }

    private void validateExistingToken(String acessToken){
        if(isEmpty(acessToken)){
            throw new ValidationException("Token must be informed");
        }
    }
}
