package com.example.session.security.dto.request;

import com.example.session.user.model.RoleEnum;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.List;

@Getter
@Setter
@Accessors
@NoArgsConstructor
public class RegisterRequest extends LoginRequest {
    List<RoleEnum> roles;
}
