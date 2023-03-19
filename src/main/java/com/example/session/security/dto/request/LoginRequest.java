package com.example.session.security.dto.request;

import lombok.Data;

@Data
public class LoginRequest {
    String username;
    String password;
}
