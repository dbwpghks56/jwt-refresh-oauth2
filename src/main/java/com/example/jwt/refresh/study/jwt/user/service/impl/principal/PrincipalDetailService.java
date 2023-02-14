package com.example.jwt.refresh.study.jwt.user.service.impl.principal;

import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import com.example.jwt.refresh.study.jwt.user.domain.model.Member;
import com.example.jwt.refresh.study.jwt.user.domain.repository.MemberRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Primary;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
@Primary
public class PrincipalDetailService implements UserDetailsService {
    private final MemberRepository memberRepository;

    @Override
    @Transactional(readOnly = true)
    public PrincipalDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Member member = memberRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("해당유저를 찾을 수 없습니다."));

        PrincipalDetails principalDetails = PrincipalDetails.builder()
                .memberSeq(member.getSeq())
                .email(member.getEmail())
                .password(member.getPassword())
                .eRole(ERole.ROLE_TRANS_USER)
                .nickname(member.getNickname())
                .build();

        return principalDetails;
    }
}
