package com.example.jwt.refresh.study.jwt.auth.domain.model;

import static com.querydsl.core.types.PathMetadataFactory.*;

import com.querydsl.core.types.dsl.*;

import com.querydsl.core.types.PathMetadata;
import javax.annotation.processing.Generated;
import com.querydsl.core.types.Path;


/**
 * QRole is a Querydsl query type for Role
 */
@Generated("com.querydsl.codegen.DefaultEntitySerializer")
public class QRole extends EntityPathBase<Role> {

    private static final long serialVersionUID = -538981514L;

    public static final QRole role1 = new QRole("role1");

    public final NumberPath<Long> id = createNumber("id", Long.class);

    public final EnumPath<com.example.jwt.refresh.study.jwt.auth.role.ERole> role = createEnum("role", com.example.jwt.refresh.study.jwt.auth.role.ERole.class);

    public QRole(String variable) {
        super(Role.class, forVariable(variable));
    }

    public QRole(Path<? extends Role> path) {
        super(path.getType(), path.getMetadata());
    }

    public QRole(PathMetadata metadata) {
        super(Role.class, metadata);
    }

}

