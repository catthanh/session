package com.example.session.security;

import com.example.session.common.dto.response.Response;
import com.example.session.security.dto.request.LoginRequest;
import com.example.session.security.dto.request.RefreshRequest;
import com.example.session.security.dto.request.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@AllArgsConstructor
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    @PostMapping("/login")
    public Response login(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        return Response.ok(authService.login(loginRequest, request, response));
    }

    @PostMapping("/register")
    public Response register(@RequestBody RegisterRequest request) {
        return Response.ok(authService.register(request));
    }

    @PostMapping("/refresh")
    public Response refresh(@RequestBody RefreshRequest request) {
        return Response.ok(authService.refresh(request));
    }

    @PostMapping("/logout")
    public Response logout(HttpServletRequest request, HttpServletResponse response) {
        return Response.ok("success");
    }
}
