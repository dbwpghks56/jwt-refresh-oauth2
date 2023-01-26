package com.example.jwt.refresh.study.jwt.auth.dto.request;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@NoArgsConstructor
public class SignInRequestDto {
    private String name;
    private String username;
    private String password;
}
