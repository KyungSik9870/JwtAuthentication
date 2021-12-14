package com.github.kyungsik.jwtauthentication.config;

public class SecurityConstants {
	public static final String SECRET_KEY = "JwtToken_SecretKey";
	public static final Long ACCESS_TOKEN_EXPIRE = 1000L * 60;
	public static final Long REFRESH_TOKEN_EXPIRE = 1000L * 60 * 60;
	public static final String TOKEN_PREFIX = "Bearer ";
	public static final String HEADER_STRING = "Authorization";
}
