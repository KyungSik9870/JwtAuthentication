package com.github.kyungsik.jwtauthentication.account;

import org.springframework.stereotype.Service;

import com.github.kyungsik.jwtauthentication.domain.Account;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AccountService {

	private final AccountRepository accountRepository;

	public void saveNewAccount(SignUpForm signUpForm) {
		Account newAccount = Account.builder()
			.loginId(signUpForm.getLoginId())
			.password(signUpForm.getPassword())
			.build();
		accountRepository.save(newAccount);
	}
}
