# JWT + 2 Factor(sms 인증)

JWT 를 사용하며 2 Factor (sms 인증) 을 하는 방법에 대해서 생각하며 프로젝트를 간단히 만들었습니다.  
업무 중, 보안ㅇ 관련하여 2 Factor 인증과 동시접속을 제한해달라는 지시를 받았는데,  
이 두 문제를 같이 고려하였습니다.

## ✹ JWT (Json Web Token) 사용

#### JWT 란?

> JSON 객체를 사용해서 토큰에 정보를 저장하는 Web Token.  
> Header, Payload, Signature 로 이루어져 있습니다.

> 헤더에 담겨질때, Authorization : <type> <credentials> 의 형태를 띄고  
> type 에 대해서는 JWT 에 특정되는 표준은 없고, OAuth2 에 사용되는 Bearer 를 써도 무방함.  
> 따라서 이번 프로젝트에서는 Bearer 로 지정해서 사용하겠습니다.

## 💻 요구사항

### 1. 2 Factor 인증을 넣어 사용가능한 사용자가 맞는지 한번 더 검증이 필요.

> 방식은 자유이나, 팀원들의 의견이 sms 인증으로 좁혀짐.  
> (해당 프로젝트에서는 실제 sms 전송은 하지않고 생성만 할 것임)

### 2. 한 계정의 동시접속을 제한해야 함.

> 여러대의 PC 에서 접속을 해서는 안된다.

## 📋 구현기능 목록

###순서  
- 사용자가 id/pw 로 인증요청을 보낸다.
- AuthenticationFilter 에서 확인한다. (provider 구현하였음)
- 인증이 성공하면 sms 코드를 발급해준다. 이때 DB에 코드 인증여부는 false 로 저장.
- (사용자가 발급받은 sms 코드를 입력하는 화면은 security 에서 permitAll 처리해줌)
- 사용자가 입력한 sms 코드가 DB 값과 일치하면 인증여부를 true 로 업데이트.
- Authorization Filter 에서는 인증여부가 false 면 인가하지 않고, 체이닝을 통과하게 하고,  
  true 면 인가해줌.
- Access Token 이 만료됐다면, Cookie 에서 refresh 토큰을 찾아 유효성을 검사하고,  
  Access Token 을 재발급해준다. 

1. JWT 구현
    - JWT 를 구현하기 위해 Authentication Filter 커스텀
    - JWT 를 구현하기 위해 Authentication Provider 커스텀
    - JWT 를 구현하기 위해 Authorization Filter 커스텀
2. 인증이 성공했을때, sms 코드를 발급할 것.
   ```java
   public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
   
      ...   
   
      @SneakyThrows
      @Override
      protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
      Authentication authResult) throws IOException, ServletException {
         String username = (authResult.getPrincipal()).toString();
         JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(customUserDetailsService);
         String accessToken = jwtTokenProvider.generateAccessToken(username);
         String refreshToken = jwtTokenProvider.generateRefreshToken(username);
      
          // Issue Refresh Token
          Cookie refreshTokenCookie = cookieUtil.create("refreshToken", refreshToken);
          response.addCookie(refreshTokenCookie);
      
          // Save Refresh Token
          String smsCode = getRandomSMSCodeString();
   
          Account account = accountRepository.findByLoginId(username)
              .orElseThrow(ChangeSetPersister.NotFoundException::new);
          account.setRefreshToken(refreshToken);
          account.setSmsCode(smsCode);
          account.setVerified(false);
          accountRepository.save(account);
      
          LoginResponse login = LoginResponse.builder()
              .nickname(username)
              .accessToken(TOKEN_PREFIX + accessToken)
              .code(CustomErrorCodes.OK.getCode())
              .message(CustomErrorCodes.OK.getStatus())
              .build();
      
          MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter();
          MediaType jsonMimeType = MediaType.APPLICATION_JSON;
      
          if (jsonConverter.canWrite(login.getClass(), jsonMimeType)) {
              jsonConverter.write(login, jsonMimeType, new ServletServerHttpResponse(response));
          }
      }
   }
   ```
3. Authorization filter 에서 sms 코드 인증 여부 판단.
   ```java
   public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
   
       ... 
   
       @Override
       protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
           throws IOException, ServletException {
   
           String header = request.getHeader(HEADER_STRING);
           if (header == null || !header.startsWith(TOKEN_PREFIX)) {
               chain.doFilter(request, response);
               return;
           }
   
           String refreshTokenValue = null;
           // try-catch phrase for expired token and issue refresh token
           try {
               if (jwtTokenProvider.validateToken(header)) {
                   String username = jwtTokenProvider.getUsername(header.replace(TOKEN_PREFIX, ""));
                   Account account = this.customUserDetailsService.loadUserByUsername(username);
   
                   if (!account.isVerified()) {
                       chain.doFilter(request, response);
                       return;
                   }
                   UsernamePasswordAuthenticationToken authentication = getAuthentication(request);
                   SecurityContextHolder.getContext().setAuthentication(authentication);
               }
           } catch (SignatureException exception) {
               log.error("JWT signature does not match");
           } catch (ExpiredJwtException exception) {
               Cookie refreshToken = cookieUtil.getCookie(request, "refreshToken");
               if (refreshToken != null) {
                   refreshTokenValue = refreshToken.getValue();
               }
           } catch (JwtException exception) {
               log.error("Token Tampered");
           } catch (NullPointerException exception) {
               log.error("Token is null");
           } catch (Exception e) {
               e.printStackTrace();
           }
   
           if (refreshTokenValue != null) {
               // check Refresh Token & issue Access Token
               try {
                   if (jwtTokenProvider.validateRefreshToken(refreshTokenValue)) {
                       String username = jwtTokenProvider.getUsername(refreshTokenValue);
                       UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                           username, null, new ArrayList<>());
                       SecurityContextHolder.getContext().setAuthentication(token);
   
                       String newAccessTokenValue = jwtTokenProvider.generateAccessToken(username);
                       LoginResponse loginResponse = LoginResponse.builder()
                           .code(CustomErrorCodes.ISSUE_ACCESS_TOKEN_BY_REFRESH_TOKEN.getCode())
                           .accessToken(newAccessTokenValue)
                           .build();
   
                       MappingJackson2HttpMessageConverter jsonConverter = new MappingJackson2HttpMessageConverter();
                       MediaType jsonMimeType = MediaType.APPLICATION_JSON;
   
                       if (jsonConverter.canWrite(loginResponse.getClass(), jsonMimeType)) {
                           jsonConverter.write(loginResponse, jsonMimeType, new ServletServerHttpResponse(response));
                       }
                   }
               } catch (Exception e) {
                   e.printStackTrace();
               }
           }
   
           chain.doFilter(request, response);
       }     
   }
   ```
4. Refresh Token 으로 동시접속 제어.

> Refresh Token 을 접속할때 마다 새로 저장하고, Access Token 의 유효기간을 짧게 유지한다.
> 그러면 Access Token 을 새로 발급받을때, 다른 곳에서 한번 더 접속했다면 Refresh Token 값이 달라져
> Access Token 을 발급받지 못할 것임.

## Next - step
Redis 를 이용하여 Refresh Token 및 로그인 관리.