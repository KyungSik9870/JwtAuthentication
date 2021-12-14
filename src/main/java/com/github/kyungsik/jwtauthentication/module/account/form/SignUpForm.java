package com.github.kyungsik.jwtauthentication.module.account.form;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

import org.hibernate.validator.constraints.Length;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignUpForm {
	@NotBlank
	@Length(min = 3, max = 20)
	private String nickname;

	@Pattern(regexp = "^[a-z0-9]{3,20}$")
	private String loginId;

	@Length(min = 8, max = 50)
	private String password;
}
