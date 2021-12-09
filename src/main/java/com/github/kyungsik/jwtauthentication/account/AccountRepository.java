package com.github.kyungsik.jwtauthentication.account;

import org.springframework.data.jpa.repository.JpaRepository;

import com.github.kyungsik.jwtauthentication.domain.Account;

public interface AccountRepository extends JpaRepository<Account, Long> {
	boolean existsByLoginId(String loginId);

	boolean existsByNickname(String nickname);
}
