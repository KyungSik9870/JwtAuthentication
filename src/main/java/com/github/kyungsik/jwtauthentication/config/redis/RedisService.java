package com.github.kyungsik.jwtauthentication.config.redis;

import java.time.Duration;

import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RedisService {

	private final RedisTemplate redisTemplate;

	public void setValues(String key, String data){
		ValueOperations<String, String> values = redisTemplate.opsForValue();
		values.set(key, data, Duration.ofMinutes(3));
	}

	public String getValues(String key){
		ValueOperations<String, String> values = redisTemplate.opsForValue();
		return values.get(key);
	}

	public void delValues(String key) {
		redisTemplate.delete(key.substring(7));
	}
}
