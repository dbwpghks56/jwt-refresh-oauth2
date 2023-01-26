package com.example.jwt.refresh.study.jwt.user.domain.model;

import com.example.jwt.refresh.study.jwt.auth.domain.model.Role;
import com.example.jwt.refresh.study.jwt.auth.domain.repository.RoleRepository;
import com.example.jwt.refresh.study.jwt.auth.role.ERole;
import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.*;
import org.springframework.beans.factory.annotation.Autowired;

import javax.persistence.*;
import java.util.HashSet;
import java.util.Set;

@Entity
@Table(name = "tb_member")
@Getter
@ToString
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long seq;

    private String email;
    @JsonIgnore
    private String password;
    private String nickname;

//    @JsonIgnore
//    @ManyToMany
//    @JoinTable(
//            name = "tb_member_role",
//            joinColumns = @JoinColumn(name = "member_seq"),
//            inverseJoinColumns = @JoinColumn(name = "role_name")
//    )
//    @ToString.Exclude
    @Enumerated(EnumType.STRING)
    private ERole roles;

    @Builder
    public Member(Long seq, String email, String password, String nickname, ERole eRole) {
        this.seq = seq;
        this.email = email;
        this.password = password;
        this.nickname = nickname;
        this.roles = eRole;
    }
}
