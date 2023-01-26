package com.example.jwt.refresh.study.jwt.boot.exception;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;
import org.springframework.http.HttpStatus;

@Getter
@ToString
@NoArgsConstructor
public class RestException extends RuntimeException {
    private HttpStatus httpStatus;
    private String message;

    @Builder
    public RestException(HttpStatus httpStatus, String message) {
        this.httpStatus = httpStatus;
        this.message =message;
    }
}
