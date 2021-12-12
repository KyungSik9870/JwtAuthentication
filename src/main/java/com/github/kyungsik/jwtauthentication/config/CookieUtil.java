package com.github.kyungsik.jwtauthentication.config;

import static com.github.kyungsik.jwtauthentication.config.SecurityConstants.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import org.springframework.stereotype.Component;

@Component
public class CookieUtil {
	public Cookie create(String cookieName, String value) {
		Cookie cookie = new Cookie(cookieName, value);
		cookie.setHttpOnly(true);
		cookie.setMaxAge(Math.toIntExact(ACCESS_TOKEN_EXPIRE));
		cookie.setPath("/");

		return cookie;
	}

	public Cookie getCookie(HttpServletRequest req, String cookieName) {
		final Cookie[] cookies = req.getCookies();
		for (Cookie cookie : cookies) {
			if (cookie.getName().equals(cookieName)) {
				return cookie;
			}
		}
		return null;
	}
}
