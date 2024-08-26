package com.adm.security;

import com.adm.entity.User;
import com.adm.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class JdbcAuthenticationManager implements AuthenticationManager {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public JdbcAuthenticationManager(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        User user = (User) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();

        Optional<User> userDB = userRepository.findByEmail(user.getEmail());

        if (userDB.isPresent()) {
            if (passwordEncoder.matches(password, userDB.get().getPassword())) {
                return new UsernamePasswordAuthenticationToken(userDB, password, null);
            } else {
                throw new BadCredentialsException("Invalid credentials");
            }
        }

        return null;
    }
}
