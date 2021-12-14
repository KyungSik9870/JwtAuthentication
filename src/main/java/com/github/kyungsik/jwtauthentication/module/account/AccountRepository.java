package com.github.kyungsik.jwtauthentication.module.account;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.github.kyungsik.jwtauthentication.domain.Account;

public interface AccountRepository extends JpaRepository<Account, Long> {
	boolean existsByLoginId(String loginId);

	boolean existsByNickname(String nickname);

	Optional<Account> findByLoginId(String username);
}
