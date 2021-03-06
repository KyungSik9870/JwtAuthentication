package com.github.kyungsik.jwtauthentication.module.account.validator;

import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.Validator;

import com.github.kyungsik.jwtauthentication.module.account.AccountRepository;
import com.github.kyungsik.jwtauthentication.module.account.form.SignUpForm;

import lombok.RequiredArgsConstructor;

@Component
@RequiredArgsConstructor
public class SignUpFormValidator implements Validator {

	private final AccountRepository accountRepository;

	@Override
	public boolean supports(Class<?> clazz) {
		return clazz.isAssignableFrom(SignUpForm.class);
	}

	@Override
	public void validate(Object target, Errors errors) {
		SignUpForm signUpForm = (SignUpForm)target;
		if (accountRepository.existsByLoginId(signUpForm.getLoginId())) {
			errors.rejectValue("loginId", "invalid loginId", new Object[] {signUpForm.getLoginId()}, "이미 사용중인 아이디입니다.");
		}
		if (accountRepository.existsByNickname(signUpForm.getNickname())) {
			errors.rejectValue("nickname", "invalid nickname", new Object[] {signUpForm.getNickname()},
				"이미 사용중인 닉네임입니다.");
		}
	}
}
