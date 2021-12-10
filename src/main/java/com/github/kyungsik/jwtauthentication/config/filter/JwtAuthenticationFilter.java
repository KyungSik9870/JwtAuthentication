package com.github.kyungsik.jwtauthentication.config.filter;

import static com.github.kyungsik.jwtauthentication.config.SecurityConstants.*;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.github.kyungsik.jwtauthentication.account.LoginResponse;
import com.github.kyungsik.jwtauthentication.config.JwtTokenProvider;

public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
		setFilterProcessesUrl("/account/login");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws
		AuthenticationException {
		String loginId = request.getParameter("loginId");
		String password = request.getParameter("password");

		return authenticationManager.authenticate(
			new UsernamePasswordAuthenticationToken(
				loginId,
				password,
				new ArrayList<>()));
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authResult) throws IOException, ServletException {
		JwtTokenProvider jwtTokenProvider = new JwtTokenProvider();

		String username = ((User)authResult.getPrincipal()).getUsername();
		String accessToken = jwtTokenProvider.generateAccessToken(username);

		LoginResponse login = new LoginResponse();
		login.setNickname(username);
		login.setAccessToken(TOKEN_PREFIX + accessToken);

		MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter();
		MediaType jsonMimeType = MediaType.APPLICATION_JSON;

		if (jsonConverter.canWrite(login.getClass(), jsonMimeType)) {
			jsonConverter.write(login, jsonMimeType, new ServletServerHttpResponse(response));
		}
	}
}
