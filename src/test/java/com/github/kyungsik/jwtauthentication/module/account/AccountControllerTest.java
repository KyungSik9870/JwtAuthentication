package com.github.kyungsik.jwtauthentication.module.account;

import static org.assertj.core.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.json.JSONObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.github.kyungsik.jwtauthentication.domain.Account;
import com.github.kyungsik.jwtauthentication.domain.Role;

@SpringBootTest
@AutoConfigureMockMvc
class AccountControllerTest {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private AccountRepository accountRepository;

	@Autowired
	private PasswordEncoder passwordEncoder;

	Account ACCOUNT_1;
	Account ACCOUNT_2;

	@BeforeEach
	void setUp() {
		ACCOUNT_1 = Account.builder()
			.id(1L)
			.loginId("kyungsik")
			.nickname("kyungsik")
			.password(passwordEncoder.encode("12345678"))
			.role(Role.ADMIN)
			.build();
		ACCOUNT_2 = Account.builder()
			.id(2L)
			.loginId("test")
			.nickname("test")
			.password(passwordEncoder.encode("12345678"))
			.role(Role.ADMIN)
			.build();
		accountRepository.save(ACCOUNT_1);
		accountRepository.save(ACCOUNT_2);
	}

	@DisplayName("회원가입 페이지 정상호출 테스트")
	@Test
	void singUpForm() throws Exception {
		mockMvc.perform(get("/sign-up"))
			.andExpect(status().isOk())
			.andExpect(view().name("account/sign-up"))
			.andExpect(model().attributeExists("signUpForm"));
	}

	@DisplayName("회원가입 - 입력값 오류")
	@ParameterizedTest
	@CsvSource(value = {"kyungsik:kyung:12345678", "kyung:kyungsik:12345678",
		"testUser:testUser:123456"}, delimiter = ':')
	void signUpForm_with_wrong_param(String loginId, String nickname, String password) throws Exception {
		mockMvc.perform(
			post("/sign-up")
				.param("loginId", loginId)
				.param("nickname", nickname)
				.param("password", password)
				.with(csrf())
		)
			.andExpect(status().isOk())
			.andExpect(view().name("account/sign-up"));
	}

	@DisplayName("회원가입 - 입력값 정상")
	@ParameterizedTest
	@CsvSource(value = {"alphabet:nickname:12345678"}, delimiter = ':')
	void signUpForm_with_right_param(String loginId, String nickname, String password) throws Exception {
		mockMvc.perform(
			post("/sign-up")
				.param("loginId", loginId)
				.param("nickname", nickname)
				.param("password", password)
				.with(csrf())
		)
			.andExpect(status().isOk())
			.andExpect(view().name("login"));

		assertThat(accountRepository.existsByLoginId(loginId)).isTrue();
	}

	@DisplayName("로그인 성공 테스트")
	@Test
	public void login_success() throws Exception {
		String username = "kyungsik";
		String password = "12345678";

		MvcResult result = mockMvc.perform(
			post("/account/login")
				.param("loginId", username)
				.param("password", password)
		)
			.andExpect(status().isOk())
			.andExpect(cookie().exists("refreshToken"))
			.andReturn();

		String response = result.getResponse().getContentAsString();
		JSONObject jsonObject = new JSONObject(response);
		System.out.println(jsonObject);
		assertThat(jsonObject.getString("accessToken")).isNotBlank();
	}

	@DisplayName("로그인 성공 후 내정보 조회 테스트")
	@Test
	void name() throws Exception {
		String username = "kyungsik";
		String password = "12345678";

		MvcResult result = mockMvc.perform(
			post("/account/login")
				.param("loginId", username)
				.param("password", password)
		)
			.andExpect(status().isOk())
			.andExpect(cookie().exists("refreshToken"))
			.andReturn();

		String response = result.getResponse().getContentAsString();
		JSONObject jsonObject = new JSONObject(response);
		String accessToken = jsonObject.getString("accessToken");

		mockMvc.perform(
			get("/account/1")
				.header("Authorization", accessToken)
		).andExpect(status().isOk());
	}
}