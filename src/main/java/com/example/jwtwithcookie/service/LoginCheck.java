package com.example.jwtwithcookie.service;

import com.example.jwtwithcookie.domain.User;
import com.example.jwtwithcookie.security.JwtSecurity;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.ModelAndViewDefiningException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Arrays;
import java.util.Map;

@Component
@Slf4j
@RequiredArgsConstructor
public class LoginCheck implements HandlerInterceptor {
    public static final String COOKIE_NAME = "login_token";

    private final JwtSecurity jwtSecurity;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws ModelAndViewDefiningException {

        String token = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(LoginCheck.COOKIE_NAME)).findFirst().map(Cookie::getValue)
                .orElse("dummy");

        log.info("token : {}", token);

        try {
            Map<String, Object> info = jwtSecurity.verify(token);

            // View 에서 session.id 처럼 로그인 정보 쉽게 가져다 쓸수 있도록 request 에 verify 한 사용자 정보 설정
            User user = User.builder().id((String) info.get("id")).name((String) info.get("name")).build();

            // view 에서 login.id 로 접근가능
            request.setAttribute("login", user);
        } catch (ExpiredJwtException ex) {
            log.error("토근이 만료됨");

            ModelAndView mav = new ModelAndView("login");
            mav.addObject("return_url", request.getRequestURI());

            throw new ModelAndViewDefiningException(mav);
        } catch (JwtException ex) {
            log.error("비정상 토큰");

            ModelAndView mav = new ModelAndView("login");

            throw new ModelAndViewDefiningException(mav);
        }

        return true;
    }
}