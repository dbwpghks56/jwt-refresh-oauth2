package com.example.jwt.refresh.study.jwt.auth.dto.request;

import lombok.*;

import java.util.Set;

@Getter
@Setter
@ToString
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SignUpRequestDto {
    private String username;
    private String password;
    private String name;
    private String email;
    private String birth;
    private String gender;
    private String phone;
    private String pushToken;
    private Set<String> roles;
}
