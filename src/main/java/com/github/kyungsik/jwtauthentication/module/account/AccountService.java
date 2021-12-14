package com.github.kyungsik.jwtauthentication.module.account;

import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.github.kyungsik.jwtauthentication.domain.Account;
import com.github.kyungsik.jwtauthentication.domain.Role;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AccountService {

	private final AccountRepository accountRepository;
	private final PasswordEncoder passwordEncoder;

	public void saveNewAccount(SignUpForm signUpForm) {
		Account newAccount = Account
			.builder()
			.loginId(signUpForm.getLoginId())
			.nickname(signUpForm.getNickname())
			.password(passwordEncoder.encode(signUpForm.getPassword()))
			.role(Role.ADMIN)
			.build();
		accountRepository.save(newAccount);
	}

	public Account findInfo(Long id) throws ChangeSetPersister.NotFoundException {
		return this.accountRepository.findById(id)
			.orElseThrow(ChangeSetPersister.NotFoundException::new);
	}
}