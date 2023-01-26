package com.example.jwt.refresh.study.jwt.user.domain.model;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;
import com.querydsl.core.types.dsl.PathInits;


/**
 * QUser is a Querydsl query type for User
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QUser extends EntityPathBase<User> {

    private static final long serialVersionUID = -1085398482L;

    public static final QUser user = new QUser("user");

    public final com.example.jwt.refresh.study.jwt.boot.domain.model.QBaseEntity _super = new com.example.jwt.refresh.study.jwt.boot.domain.model.QBaseEntity(this);

    public final StringPath birth = createString("birth");

    //inherited
    public final DateTimePath<java.time.LocalDateTime> createdDtime = _super.createdDtime;

    public final StringPath email = createString("email");

    public final StringPath gender = createString("gender");

    //inherited
    public final DateTimePath<java.time.LocalDateTime> modifiedDtime = _super.modifiedDtime;

    public final StringPath name = createString("name");

    public final StringPath password = createString("password");

    public final StringPath pushToken = createString("pushToken");

    public final SetPath<com.example.jwt.refresh.study.jwt.auth.domain.model.Role, com.example.jwt.refresh.study.jwt.auth.domain.model.QRole> roles = this.<com.example.jwt.refresh.study.jwt.auth.domain.model.Role, com.example.jwt.refresh.study.jwt.auth.domain.model.QRole>createSet("roles", com.example.jwt.refresh.study.jwt.auth.domain.model.Role.class, com.example.jwt.refresh.study.jwt.auth.domain.model.QRole.class, PathInits.DIRECT2);

    public final NumberPath<Long> seq = createNumber("seq", Long.class);

    //inherited
    public final NumberPath<Integer> status = _super.status;

    public final StringPath username = createString("username");

    public QUser(String variable) {
        super(User.class, forVariable(variable));
    }

    public QUser(Path<? extends User> path) {
        super(path.getType(), path.getMetadata());
    }

    public QUser(PathMetadata metadata) {
        super(User.class, metadata);
    }

}

