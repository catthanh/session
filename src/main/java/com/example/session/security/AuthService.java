package com.example.session.security;

import com.example.session.common.utils.JwtUtils;
import com.example.session.security.dto.request.LoginRequest;
import com.example.session.security.dto.request.RefreshRequest;
import com.example.session.security.dto.request.RegisterRequest;
import com.example.session.security.dto.response.LoginResponse;
import com.example.session.security.dto.response.RegisterResponse;
import com.example.session.security.model.RefreshToken;
import com.example.session.user.UserRepository;
import com.example.session.user.UserService;
import com.example.session.user.model.Role;
import com.example.session.user.model.RoleEnum;
import com.example.session.user.model.User;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.stereotype.Service;

import java.net.http.HttpRequest;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;


@AllArgsConstructor
@Service
public class AuthService {
    private final UserRepository userRepository;
    private final JwtUtils jwtUtils;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserService userService;
    private final SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder.getContextHolderStrategy();
    private SecurityContextRepository securityContextRepository;

    public LoginResponse login(LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        Optional<User> user = userRepository.findByUsername(loginRequest.getUsername());
        if(user.isPresent()) {
            if(!passwordEncoder.matches(loginRequest.getPassword(), user.get().getPassword())) {
                throw new RuntimeException("Password is incorrect");
            }
            UsernamePasswordAuthenticationToken authentication = UsernamePasswordAuthenticationToken.authenticated(
                    loginRequest.getUsername(), loginRequest.getPassword(), userService.getAuthorities(user.get()));
            SecurityContext context = securityContextHolderStrategy.createEmptyContext();
            context.setAuthentication(authentication);
            securityContextHolderStrategy.setContext(context);
            securityContextRepository.saveContext(context, request, response);
            return LoginResponse.of(user.get());
        }
        throw new RuntimeException("User not found");
    }

    public RegisterResponse register(RegisterRequest request) {
        if(userRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        List<RoleEnum> roles= request.getRoles();
        user.setRoles(roles.stream().map(role -> new Role().setName(role)).collect(Collectors.toSet()));
        userRepository.save(user);
        return RegisterResponse.of(user);
    }

    public LoginResponse refresh(RefreshRequest request) {
        if(!jwtUtils.validateToken(request.getRefreshToken()) ) {
            throw new RuntimeException("Token is invalid");
        }
        Optional<RefreshToken> oldRefreshToken = refreshTokenRepository.findByToken(request.getRefreshToken());
        if(oldRefreshToken.isEmpty()) {
            throw new RuntimeException("Token is invalid");
        }
        if(!oldRefreshToken.get().getActive()) {
            // fire new event to set all refresh tokens with the same parent (including the parent) to inactive
            refreshTokenRepository.updateAllInvalidToken(oldRefreshToken.get().getFamily());
            throw new RuntimeException("Token reuse detected");
        }
        String username = jwtUtils.extractUsername(request.getRefreshToken());
        Optional<User> user = userRepository.findByUsername(username);
        if(user.isPresent()) {
            String newAccessToken = jwtUtils.generateToken(user.get().getUsername(), user.get().getRoles().stream().map(role -> role.getName().name()).toList());
            String newRefreshToken = jwtUtils.generateToken(user.get().getUsername(), user.get().getRoles().stream().map(role -> role.getName().name()).toList(),true);
            refreshTokenRepository.save(new RefreshToken().setToken(newRefreshToken).setActive(true).setFamily(oldRefreshToken.get().getFamily()));
            refreshTokenRepository.save(oldRefreshToken.get().setToken(request.getRefreshToken()).setActive(false));
            return LoginResponse.of(user.get(), newAccessToken, newRefreshToken);
        }
        throw new RuntimeException("User not found");
    }
}
