package com.github.kyungsik.jwtauthentication.module.account.form;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class SmsCodeForm {
	private String mobilePhoneNumber;
	private String smsCode;
}
