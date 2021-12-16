package com.github.kyungsik.jwtauthentication.config.provider;

import static com.github.kyungsik.jwtauthentication.config.SecurityConstants.*;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.springframework.stereotype.Component;

import com.github.kyungsik.jwtauthentication.domain.Account;
import com.github.kyungsik.jwtauthentication.module.account.CustomUserDetailsService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtTokenProvider {

	@Resource(name = "customUserDetailsService")
	private final CustomUserDetailsService customUserDetailsService;

	public String generateAccessToken(String username) {
		return generateToken(username, ACCESS_TOKEN_EXPIRE);
	}

	public String generateRefreshToken(String username) {
		return generateToken(username, REFRESH_TOKEN_EXPIRE);
	}

	public boolean validateToken(String header) throws Exception {
		String tokenValue = header.replace(TOKEN_PREFIX, "");
		Jwts.parser()
			.setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
			.parseClaimsJws(tokenValue);
		return true;
	}

	public boolean validateRefreshToken(String refreshTokenValue) throws Exception {
		String username = getUsername(refreshTokenValue);
		Account account = this.customUserDetailsService.loadUserByUsername(username);
		return account.getRefreshToken().equals(refreshTokenValue) && validateToken(refreshTokenValue);
	}

	private String generateToken(String username, Long expireTime) {
		JwtBuilder jwtBuilder = Jwts.builder()
			.setSubject(username)
			.setHeader(createHeader())
			.setClaims(createClaims(username))
			.setExpiration(new Date(System.currentTimeMillis() + expireTime))
			.signWith(SignatureAlgorithm.HS512, createSigningKey());

		return jwtBuilder.compact();
	}

	public String getUsername(String token) {
		Claims claims = getClaimsFromToken(token);
		return claims.get("username").toString();
	}

	private Map<String, Object> createHeader() {
		Map<String, Object> header = new HashMap<>();
		header.put("typ", "JWT");
		header.put("alg", "HS512");
		header.put("regDate", System.currentTimeMillis());
		return header;
	}

	private Map<String, Object> createClaims(String username) {
		Map<String, Object> claims = new HashMap<>();
		claims.put("username", username);
		return claims;
	}

	private Key createSigningKey() {
		byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(SECRET_KEY);
		return new SecretKeySpec(apiKeySecretBytes, SignatureAlgorithm.HS512.getJcaName());
	}

	public String createAuthenticationFromToken(String accessTokenValue) {
		return getUsernameFromToken(accessTokenValue);
	}

	private String getUsernameFromToken(String accessTokenValue) {
		Claims claims = getClaimsFromToken(accessTokenValue);
		return claims.get("username").toString();
	}

	private Claims getClaimsFromToken(String accessTokenValue) {
		return Jwts.parser()
			.setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY))
			.parseClaimsJws(accessTokenValue)
			.getBody();
	}
}
