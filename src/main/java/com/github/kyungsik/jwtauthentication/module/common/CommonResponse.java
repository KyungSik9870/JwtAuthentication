package com.github.kyungsik.jwtauthentication.module.common;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.SuperBuilder;

@Getter
@Setter
@SuperBuilder
@AllArgsConstructor
public class CommonResponse {
	private Integer code;
	private String message;
}
