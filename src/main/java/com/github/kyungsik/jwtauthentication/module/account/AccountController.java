package com.github.kyungsik.jwtauthentication.module.account;

import static com.github.kyungsik.jwtauthentication.config.SecurityConstants.*;

import javax.validation.Valid;

import org.springframework.data.crossstore.ChangeSetPersister;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;

import com.github.kyungsik.jwtauthentication.config.provider.JwtTokenProvider;
import com.github.kyungsik.jwtauthentication.domain.Account;
import com.github.kyungsik.jwtauthentication.module.account.form.SignUpForm;
import com.github.kyungsik.jwtauthentication.module.account.form.SmsCodeForm;
import com.github.kyungsik.jwtauthentication.module.account.validator.SignUpFormValidator;
import com.github.kyungsik.jwtauthentication.module.common.CommonResponse;
import com.github.kyungsik.jwtauthentication.module.common.CustomErrorCodes;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class AccountController {

	private final SignUpFormValidator signUpFormValidator;
	private final AccountService accountService;
	private final JwtTokenProvider jwtTokenProvider;

	@InitBinder
	public void initBinding(WebDataBinder webDataBinder) {
		webDataBinder.addValidators(signUpFormValidator);
	}

	@GetMapping("/login")
	public String login() {
		return "login";
	}

	@GetMapping("/sign-up")
	public String signUp(Model model) {
		model.addAttribute(new SignUpForm());
		return "account/sign-up";
	}

	@PostMapping("/sign-up")
	public String signUpSubmit(@Valid SignUpForm signUpForm, Errors errors) {
		if (errors.hasErrors()) {
			return "account/sign-up";
		}
		accountService.saveNewAccount(signUpForm);
		return "login";
	}

	@GetMapping("/account/{id}")
	public ResponseEntity<Account> myInfo(@PathVariable Long id) throws ChangeSetPersister.NotFoundException {
		Account account = this.accountService.findInfo(id);
		return new ResponseEntity<>(account, HttpStatus.OK);
	}

	@GetMapping("/sms/check")
	public String checkSMSCode() {
		return "account/check-sms";
	}

	@PostMapping("/sms/verify")
	public ResponseEntity<CommonResponse> verifySMSCode(@RequestHeader(HEADER_STRING) String token,
		String smsCode) throws
		ChangeSetPersister.NotFoundException {
		String username = jwtTokenProvider.getUsername(token.replace(TOKEN_PREFIX, ""));
		Account account = this.accountService.findByUserName(username);

		CommonResponse.CommonResponseBuilder commonResponse = CommonResponse.builder();

		if (!account.getSmsCode().equals(smsCode)) {
			commonResponse.code(CustomErrorCodes.FAIL_SMS_CODE.getCode());
			commonResponse.message(CustomErrorCodes.FAIL_SMS_CODE.getStatus());
			return new ResponseEntity<>(commonResponse.build(), HttpStatus.OK);
		}
		account.setVerified(true);
		this.accountService.saveAccount(account);

		commonResponse.code(CustomErrorCodes.OK.getCode());
		commonResponse.message(CustomErrorCodes.OK.getStatus());
		return new ResponseEntity<>(commonResponse.build(), HttpStatus.OK);
	}
}
