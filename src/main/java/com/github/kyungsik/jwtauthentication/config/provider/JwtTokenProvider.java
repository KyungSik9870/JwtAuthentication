package com.github.kyungsik.jwtauthentication.config.provider;

import static com.github.kyungsik.jwtauthentication.config.SecurityConstants.*;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.github.kyungsik.jwtauthentication.account.CustomUserDetailsService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;

@Component
@Slf4j
public class JwtTokenProvider {

	@Autowired
	private CustomUserDetailsService customUserDetailsService;

	public String generateAccessToken(String username) {
		return generateToken(username, ACCESS_TOKEN_EXPIRE);
	}

	public String generateRefreshToken(String username) {
		return generateToken(username, REFRESH_TOKEN_EXPIRE);
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

	public boolean validateToken(String header) {
		String tokenValue = header.replace(TOKEN_PREFIX, "");
		try {
			Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(SECRET_KEY)).parseClaimsJws(tokenValue);
			return true;
		} catch (SignatureException exception) {
			log.error("JWT signature does not match");
			return false;
		} catch (ExpiredJwtException exception) {
			log.error("Token Expired");
			return false;
		} catch (JwtException exception) {
			log.error("Token Tampered");
			return false;
		} catch (NullPointerException exception) {
			log.error("Token is null");
			return false;
		}
	}
}
