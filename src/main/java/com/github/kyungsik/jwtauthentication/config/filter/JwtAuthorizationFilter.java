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

@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

	@Autowired
	private JwtTokenProvider jwtTokenProvider;

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

		if (jwtTokenProvider.validateToken(header)){
			UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
			log.info("Issue Token");
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
