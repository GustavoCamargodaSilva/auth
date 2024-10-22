package br.com.microservice.stateful_auth_api.core.service;
import br.com.microservice.stateful_auth_api.core.dto.AuthRequest;
import br.com.microservice.stateful_auth_api.core.dto.AuthUserResponse;
import br.com.microservice.stateful_auth_api.core.dto.TokenDTO;
import br.com.microservice.stateful_auth_api.core.infra.exception.AuthenticationException;
import br.com.microservice.stateful_auth_api.core.model.User;
import org.springframework.security.crypto.password.PasswordEncoder;
import br.com.microservice.stateful_auth_api.core.repository.UserRepository;
import jakarta.validation.ValidationException;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;
import static org.springframework.util.ObjectUtils.isEmpty;

@Service
@AllArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenService tokenService;

    public TokenDTO login(AuthRequest authRequest){

        var user = findByUserName(authRequest.username());

        var acessToken = tokenService.createToken(user.getUsername());

        validatePassword(authRequest.password(), user.getPassword());

        return new TokenDTO(acessToken);
    }

    public AuthUserResponse getAuthenticatedUser(String acessToken){

        var TokenData = tokenService.getTokenData(acessToken);

        var user = findByUserName(TokenData.username());

        return new AuthUserResponse(user.getId(), user.getUsername());
    }

    public void logout(String acessToken){

        tokenService.deleteToken(acessToken);
    }

    private User findByUserName(String username){

        return userRepository.findByUsername(username)

                .orElseThrow(() -> new ValidationException("User not found"));
    }

    public TokenDTO validateToken(String acessToken){

        validateExistingToken(acessToken);

        var valid = tokenService.validateAcessToken(acessToken);

        if(valid){

            return new TokenDTO(acessToken);

        }

        throw new AuthenticationException("Invalid token");
    }


    private void validatePassword(String rawPassword, String encodedPassword){

        if(isEmpty(rawPassword)){

            throw new ValidationException("Password must be informed");

        }
        if(!passwordEncoder.matches(rawPassword, encodedPassword)){

            throw new ValidationException("Invalid password");

        }
    }

    private void validateExistingToken(String acessToken){

        if(isEmpty(acessToken)){

            throw new ValidationException("Token must be informed");

        }
    }
}
