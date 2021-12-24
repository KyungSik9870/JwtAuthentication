package com.github.kyungsik.jwtauthentication.config.provider;

import java.util.List;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.github.kyungsik.jwtauthentication.domain.Account;
import com.github.kyungsik.jwtauthentication.module.account.CustomUserDetailsService;

import lombok.RequiredArgsConstructor;
import lombok.SneakyThrows;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

	private final CustomUserDetailsService customUserDetailsService;
	private final PasswordEncoder passwordEncoder;

	@SneakyThrows
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		UsernamePasswordAuthenticationToken authToken = (UsernamePasswordAuthenticationToken)authentication;
		Account userDetails = this.customUserDetailsService.loadUserByUsername(authToken.getName());

		if (!passwordEncoder.matches(authToken.getCredentials().toString(), userDetails.getPassword())) {
			throw new BadCredentialsException("invalid username or password");
		}

		List<GrantedAuthority> authorities = (List<GrantedAuthority>)userDetails.getAuthorities();
		return new UsernamePasswordAuthenticationToken(userDetails.getUsername(), userDetails.getPassword(),
			authorities);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
