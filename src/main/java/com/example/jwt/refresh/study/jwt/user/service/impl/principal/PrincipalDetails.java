package com.example.jwt.refresh.study.jwt.user.service.impl.principal;

import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

@Getter
@ToString
@NoArgsConstructor
public class PrincipalDetails implements UserDetails {
    private Long memberSeq;
    private String password;
    private String email;
    private String nickname;
    private ERole eRole;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        ArrayList<GrantedAuthority> auth = new ArrayList<>();
        auth.add(new SimpleGrantedAuthority(eRole.name()));
        return auth;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

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

    @Builder
    public PrincipalDetails(Long memberSeq, String password, String email, String nickname, ERole eRole) {
        this.memberSeq = memberSeq;
        this.password = password;
        this.email = email;
        this.nickname = nickname;
        this.eRole = eRole;
    }
}
