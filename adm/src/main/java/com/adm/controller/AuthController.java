package com.adm.controller;

import com.adm.entity.User;
import com.adm.repository.UserRepository;
import com.adm.security.jwt.JwtTokenUtil;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@RestController
@RequestMapping("${rest.api.preffix}/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;

    private final JwtTokenUtil jwtTokenUtil;

    private final UserRepository userRepository;

    private final Counter jwtProducedCounter;

    private final Counter invalidCredentialCounter;


    public AuthController(AuthenticationManager authenticationManager, JwtTokenUtil jwtTokenUtil, UserRepository userRepository, MeterRegistry registry) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenUtil = jwtTokenUtil;
        this.userRepository = userRepository;

        jwtProducedCounter = Counter.builder("adm_backend_jwt_generated_sum")
                .description("Number of JWT produced")
                .register(registry);

        invalidCredentialCounter = Counter.builder("adm_backend_invalid_credential_sum")
                .description("Number of invalid credentials when a sign in is attempt")
                .register(registry);
    }

    @PostMapping("signin")
    public ResponseEntity<Map<String, Object>> authenticateUser(@RequestBody User user) {
        Map<String, Object> response = new HashMap<>();

        try {
            Authentication authenticate = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(user, user.getPassword()));

            if (authenticate.isAuthenticated()) {
                Optional<User> userDB = userRepository.findByEmail(user.getEmail());
                String accessToken = jwtTokenUtil.generateAccessToken(userDB.get());

                response.put("token", accessToken);

                jwtProducedCounter.increment();
            }

            return ResponseEntity.ok().body(response);
        } catch (BadCredentialsException ex) {
            invalidCredentialCounter.increment();
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }
}
