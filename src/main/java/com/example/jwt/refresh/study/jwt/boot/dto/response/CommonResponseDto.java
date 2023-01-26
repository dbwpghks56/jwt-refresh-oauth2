package com.example.jwt.refresh.study.jwt.boot.dto.response;

import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.ToString;

@Getter
@ToString
@NoArgsConstructor
public class CommonResponseDto<T> {
    private Boolean success;
    private Integer status;
    private String message;
    private T data;

    @Builder
    public CommonResponseDto(Boolean success, Integer status, String message, T data) {
        this.success = success;
        this.status = status;
        this.message = message;
        this.data = data;
    }
}
