package com.github.kyungsik.jwtauthentication.config.filter;

import static com.github.kyungsik.jwtauthentication.config.SecurityConstants.*;

import java.io.IOException;
import java.util.ArrayList;

import javax.annotation.Resource;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.github.kyungsik.jwtauthentication.config.CookieUtil;
import com.github.kyungsik.jwtauthentication.config.provider.JwtTokenProvider;
import com.github.kyungsik.jwtauthentication.domain.Account;
import com.github.kyungsik.jwtauthentication.module.account.AccountRepository;
import com.github.kyungsik.jwtauthentication.module.account.CustomUserDetailsService;
import com.github.kyungsik.jwtauthentication.module.account.LoginResponse;
import com.github.kyungsik.jwtauthentication.module.common.CustomErrorCodes;

import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;

/**
 * Authentication Filter(인증)
 *
 * 인증.
 * id/pw 같은게 맞는지 확인해서
 * A 사용자가 A 인 것을 확인(인증)
 */
@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

	private final AuthenticationManager authenticationManager;
	private final CookieUtil cookieUtil = new CookieUtil();
	private final AccountRepository accountRepository;

	@Resource(name = "customUserDetailsService")
	private CustomUserDetailsService customUserDetailsService;

	public JwtAuthenticationFilter(AuthenticationManager authenticationManager,
		AccountRepository accountRepository) {
		this.authenticationManager = authenticationManager;
		this.accountRepository = accountRepository;
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

	@SneakyThrows
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
		Authentication authResult) throws IOException, ServletException {
		String username = (authResult.getPrincipal()).toString();
		JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(customUserDetailsService);
		String accessToken = jwtTokenProvider.generateAccessToken(username);
		String refreshToken = jwtTokenProvider.generateRefreshToken(username);

		// TODO Issue Refresh Token
		Cookie refreshTokenCookie = cookieUtil.create("refreshToken", refreshToken);
		response.addCookie(refreshTokenCookie);

		// TODO Save Refresh Token
		Account account = accountRepository.findByLoginId(username).orElseThrow(ChangeSetPersister.NotFoundException::new);
		account.setRefreshToken(refreshToken);
		accountRepository.save(account);

		LoginResponse login = LoginResponse.builder()
			.nickname(username)
			.accessToken(TOKEN_PREFIX + accessToken)
			.code(CustomErrorCodes.OK.getCode())
			.message(CustomErrorCodes.OK.getStatus())
			.build();

		MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter();
		MediaType jsonMimeType = MediaType.APPLICATION_JSON;

		if (jsonConverter.canWrite(login.getClass(), jsonMimeType)) {
			jsonConverter.write(login, jsonMimeType, new ServletServerHttpResponse(response));
		}
	}
}
