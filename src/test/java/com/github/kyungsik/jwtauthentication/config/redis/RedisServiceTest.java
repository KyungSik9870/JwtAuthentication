package com.github.kyungsik.jwtauthentication.config.redis;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import com.github.kyungsik.jwtauthentication.config.RedisConfig;

@SpringBootTest
@Import(RedisConfig.class)
class RedisServiceTest {

	@Autowired
	RedisTemplate<String, String> redisTemplate;

	@Test
	void redis_connection_test() {
		final String key = "key";
		final String data = "data";

		ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
		valueOperations.set(key, data);

		String result = valueOperations.get(key);
		assertThat(result.equals(data)).isTrue();
	}
}