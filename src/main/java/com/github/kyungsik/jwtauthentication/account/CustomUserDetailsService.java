package com.github.kyungsik.jwtauthentication.account;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.github.kyungsik.jwtauthentication.domain.Account;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	private final AccountRepository accountRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Account account = this.accountRepository.findByLoginId(username)
			.orElseThrow(() -> new UsernameNotFoundException(username));

		List<GrantedAuthority> authorities = new ArrayList<>();
		// authorities.add(new SimpleGrantedAuthority(account.getRole().name()));
		return new User(username, account.getPassword(), authorities);
	}
}
