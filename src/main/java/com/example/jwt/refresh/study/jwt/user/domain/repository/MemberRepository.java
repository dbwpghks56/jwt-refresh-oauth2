package com.example.jwt.refresh.study.jwt.user.domain.repository;

import com.example.jwt.refresh.study.jwt.user.domain.model.Member;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Optional<Member> findByEmail(String email);
}
