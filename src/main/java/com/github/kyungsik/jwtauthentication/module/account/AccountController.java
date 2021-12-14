package com.github.kyungsik.jwtauthentication.module.account;

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

import com.github.kyungsik.jwtauthentication.domain.Account;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class AccountController {

	private final SignUpFormValidator signUpFormValidator;
	private final AccountService accountService;

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
}
