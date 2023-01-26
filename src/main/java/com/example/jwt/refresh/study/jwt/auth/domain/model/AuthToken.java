package com.example.jwt.refresh.study.jwt.auth.domain.model;

import com.example.jwt.refresh.study.jwt.boot.domain.model.BaseEntity;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.DynamicInsert;

import javax.persistence.*;

@Entity
@Table(name = "tb_user_auth")
@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@DynamicInsert
public class AuthToken extends BaseEntity {
    @Id
    private String seq;

    private Long userSeq;

    @Column(columnDefinition = "varchar(1000)")
    private String accessToken;

    @Column(columnDefinition = "varchar(1000)")
    private String refreshToken;

    public void updateAccessToken(String newAccessToken) {
        this.accessToken = newAccessToken;
    }
}
