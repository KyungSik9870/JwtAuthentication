package com.github.kyungsik.jwtauthentication.config.filter;

import static com.github.kyungsik.jwtauthentication.config.SecurityConstants.*;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.github.kyungsik.jwtauthentication.config.CookieUtil;
import com.github.kyungsik.jwtauthentication.config.provider.JwtTokenProvider;
import com.github.kyungsik.jwtauthentication.module.account.CustomUserDetailsService;
import com.github.kyungsik.jwtauthentication.module.account.LoginResponse;
import com.github.kyungsik.jwtauthentication.module.common.CustomErrorCodes;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.SignatureException;
import lombok.extern.slf4j.Slf4j;

/**
 * Authorization Filter (인가)
 *
 * 인증이 아닌 인가.
 * 권한이 있는지 보고 보여줄지 말지 허락하는 단계
 */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private final JwtTokenProvider jwtTokenProvider;
	private final CookieUtil cookieUtil = new CookieUtil();

	public JwtAuthorizationFilter(
		AuthenticationManager authenticationManager, CustomUserDetailsService customUserDetailsService) {
		super(authenticationManager);
		this.jwtTokenProvider = new JwtTokenProvider(customUserDetailsService);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
		throws IOException, ServletException {

		String header = request.getHeader(HEADER_STRING);
		if (header == null || !header.startsWith(TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}

		String refreshTokenValue = null;
		// try-catch phrase for expired token and issue refresh token
		try {
			if (jwtTokenProvider.validateToken(header)) {
				UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} catch (SignatureException exception) {
			log.error("JWT signature does not match");
		} catch (ExpiredJwtException exception) {
			Cookie refreshToken = cookieUtil.getCookie(request, "refreshToken");
			if (refreshToken != null) {
				refreshTokenValue = refreshToken.getValue();
			}
		} catch (JwtException exception) {
			log.error("Token Tampered");
		} catch (NullPointerException exception) {
			log.error("Token is null");
		} catch (Exception e) {
			e.printStackTrace();
		}

		if (refreshTokenValue != null) {
			// check Refresh Token & issue Access Token
			try {
				if (jwtTokenProvider.validateRefreshToken(refreshTokenValue)) {
					String username = jwtTokenProvider.getUsername(refreshTokenValue);
					UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
						username, null, new ArrayList<>());
					SecurityContextHolder.getContext().setAuthentication(token);

					String newAccessTokenValue = jwtTokenProvider.generateAccessToken(username);
					LoginResponse loginResponse = LoginResponse.builder()
						.code(CustomErrorCodes.ISSUE_ACCESS_TOKEN_BY_REFRESH_TOKEN.getCode())
						.accessToken(newAccessTokenValue)
						.build();

					MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter();
					MediaType jsonMimeType = MediaType.APPLICATION_JSON;

					if (jsonConverter.canWrite(loginResponse.getClass(), jsonMimeType)) {
						jsonConverter.write(loginResponse, jsonMimeType, new ServletServerHttpResponse(response));
					}
				}
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

		chain.doFilter(request, response);
	}

	private UsernamePasswordAuthenticationToken getAuthentication(HttpServletRequest request) {
		String token = request.getHeader(HEADER_STRING);
		if (token == null) {
			return null;
		}

		String accessTokenValue = token.replace(TOKEN_PREFIX, "");
		String username = jwtTokenProvider.createAuthenticationFromToken(accessTokenValue);
		if (username == null) {
			return null;
		}

		return new UsernamePasswordAuthenticationToken(username, null, new ArrayList<>());
	}
}
