package com.github.kyungsik.jwtauthentication.config;

import java.util.List;

import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.github.kyungsik.jwtauthentication.account.AccountRepository;
import com.github.kyungsik.jwtauthentication.domain.Account;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

	private final AccountRepository accountRepository;
	private final PasswordEncoder passwordEncoder;

	@SneakyThrows
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		// 1. authentication 을 지원하는 타입으로 변환
		UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken)authentication;
		// 2. 사용자 정보를 조회한다. 존재하지 않으면 Exception
		Account account = this.accountRepository.findByLoginId(authToken.getName())
			.orElseThrow(ChangeSetPersister.NotFoundException::new);
		// 3. 조회한 사용자와 파라미터로 받은 authentication 의 암호를 비교한다.
		if (!passwordEncoder.matches(account.getPassword(), authToken.getCredentials().toString())) {
			throw new BadCredentialsException("invalid username or password");
		}
		// 4. 사용자가 가진 권한 목록을 구한다.
		List<GrantedAuthority> authorities = (List<GrantedAuthority>)account.getAuthorities();
		// 5. 인증된 사용자에 대한 Authentication 객체를 생성해서 리턴한다.
		// Object principal, Object credentials,
		// 			Collection<? extends GrantedAuthority> authorities
		return new UsernamePasswordAuthenticationToken(new Account(account.getId(), account.getLoginId()),
			account.getPassword(), authorities);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
