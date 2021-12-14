package com.github.kyungsik.jwtauthentication.module.account;

import com.github.kyungsik.jwtauthentication.module.common.CommonResponse;

import lombok.Getter;
import lombok.experimental.SuperBuilder;

@Getter
@SuperBuilder
public class LoginResponse extends CommonResponse {
	private String nickname;
	private String accessToken;
	private String nextUrl;
}
