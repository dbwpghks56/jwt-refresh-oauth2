package com.example.jwt.refresh.study.jwt.user.domain.repository;

import com.example.jwt.refresh.study.jwt.user.domain.model.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Optional<User> findBySeq(Long userSeq);

    List<User> findBySeqIn(List<Long> userSeqList);

    Integer deleteByUsername(String username);

    Integer deleteBySeq(Long userSeq);

    Integer deleteBySeqIn(List<Long> userSeq);

    Boolean existsByUsername(String username);

}
