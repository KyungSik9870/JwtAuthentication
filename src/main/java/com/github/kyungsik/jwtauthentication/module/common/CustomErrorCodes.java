package com.github.kyungsik.jwtauthentication.module.common;

import lombok.Getter;

@Getter
public enum CustomErrorCodes {
	OK(200, "OK"),
	ISSUE_ACCESS_TOKEN_BY_REFRESH_TOKEN(201, "OK");

	private final int code;
	private final String status;

	CustomErrorCodes(int code, String status) {
		this.code = code;
		this.status = status;
	}
}
