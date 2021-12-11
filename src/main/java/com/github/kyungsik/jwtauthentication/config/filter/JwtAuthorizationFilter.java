package com.github.kyungsik.jwtauthentication.config.filter;

import static com.github.kyungsik.jwtauthentication.config.SecurityConstants.*;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.github.kyungsik.jwtauthentication.config.provider.JwtTokenProvider;

import lombok.extern.slf4j.Slf4j;

/**
 * Authorization Filter (인가)
 *
 * 인증이 아닌 인가.
 * 권한이 있는지 보고 보여줄지 말지 허락하는 단계
 */
@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	private final JwtTokenProvider jwtTokenProvider = new JwtTokenProvider();

	public JwtAuthorizationFilter(
		AuthenticationManager authenticationManager) {
		super(authenticationManager);
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws
		IOException,
		ServletException {

		String header = request.getHeader(HEADER_STRING);

		log.info("Authorization Filter IN");
		if (header == null || !header.startsWith(TOKEN_PREFIX)) {
			chain.doFilter(request, response);
			return;
		}

		// TODO add try-catch phrase for expired token and issue refresh token
		if (jwtTokenProvider.validateToken(header)){
			UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
			SecurityContextHolder.getContext().setAuthentication(authentication);
			chain.doFilter(request, response);
		}
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
