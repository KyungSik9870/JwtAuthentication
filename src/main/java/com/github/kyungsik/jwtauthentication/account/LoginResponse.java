package com.github.kyungsik.jwtauthentication.account;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class LoginResponse {
	private String nickname;
	private String accessToken;
}
