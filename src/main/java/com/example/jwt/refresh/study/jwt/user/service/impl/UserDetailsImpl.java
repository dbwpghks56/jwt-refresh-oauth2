package com.example.jwt.refresh.study.jwt.user.service.impl;

import com.example.jwt.refresh.study.jwt.auth.domain.model.Role;
import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import com.example.jwt.refresh.study.jwt.user.domain.model.User;
import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Getter
@ToString
@NoArgsConstructor
public class UserDetailsImpl implements UserDetails {
    private Long seq;
    private String username;
    private String password;
    private String name;
    private String email;
    private String birth;
    private String gender;
    private String phone;
    private String emailYn;
    private String smsYn;
    private String pushToken;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime lastPwupDtime;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime createdDtime;

    @JsonFormat(pattern = "yyyy-MM-dd HH:mm:ss")
    private LocalDateTime modifiedDtime;

    private List<ERole> roles;

    @JsonIgnore
    private Collection<? extends GrantedAuthority> authorities;
    private Integer status;

    public void setPhone(String phone) {
        this.phone = phone;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Builder
    public UserDetailsImpl(
            Long seq,
            String username,
            String password,
            String name,
            String email,
            String birth,
            String gender,
            String phone,
            String emailYn,
            String smsYn,
            String pushToken,
            LocalDateTime lastPwUpdDtime,
            LocalDateTime createdDtime,
            LocalDateTime modifiedDtime,
            List<ERole> roles,
            Collection<? extends GrantedAuthority> authorities,
            Integer status
    ) {
        this.seq = seq;
        this.username = username;
        this.password = password;
        this.name = name;
        this.email = email;
        this.birth = birth;
        this.gender = gender;
        this.phone = phone;
        this.emailYn = emailYn;
        this.smsYn = smsYn;
        this.pushToken = pushToken;
        this.lastPwupDtime = lastPwUpdDtime;
        this.createdDtime = createdDtime;
        this.modifiedDtime = modifiedDtime;
        this.roles = roles;
        this.authorities = authorities;
        this.status = status;

    }

    public static UserDetailsImpl getUserDetails(User entity) {
        List<GrantedAuthority> authorities1 = entity.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getRole().name()))
                .collect(Collectors.toList());

        List<ERole> rolesForResponse = entity.getRoles().stream()
                .map(Role::getRole)
                .collect(Collectors.toList());

        return UserDetailsImpl.builder()
                .seq(entity.getSeq())
                .username(entity.getUsername())
                .password(entity.getPassword())
                .name(entity.getName())
                .email(entity.getEmail())
                .birth(entity.getBirth())
                .gender(entity.getGender())
                .pushToken(entity.getPushToken())
                .createdDtime(entity.getCreatedDtime())
                .modifiedDtime(entity.getModifiedDtime())
                .roles(rolesForResponse)
                .authorities(authorities1)
                .status(entity.getStatus())
                .build();
    }

    @Override
    public boolean isAccountNonExpired() {return true;}

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
