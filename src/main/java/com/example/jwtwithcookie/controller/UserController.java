package com.example.jwtwithcookie.controller;

import com.example.jwtwithcookie.security.JwtSecurity;
import com.example.jwtwithcookie.service.User.LoginCheck;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Slf4j
@Controller
@RequiredArgsConstructor
public class UserController {

    private final JwtSecurity jwtSecurity;


    @GetMapping("/login")
    public String login(){
        return "login";
    }

    @PostMapping("login")
    public String login(@RequestParam String id, @RequestParam String pwd, HttpServletResponse res) {
         // 로그인 성공시 쿠키에 token 저장
        Map<String, Object> user = new HashMap<>();
        user.put("id", id);
        user.put("name", "홍길동");

        // 30분후 만료되는 jwt 만들어서 쿠키에 저장
        Cookie cookie = new Cookie(LoginCheck.COOKIE_NAME,
                jwtSecurity.token(user, Optional.of(LocalDateTime.now().plusMinutes(30))));

        cookie.setPath("/");
        cookie.setMaxAge(Integer.MAX_VALUE);

        res.addCookie(cookie);

        return "redirect:/main";
    }

    /**
     * 로그아웃 처리 : 쿠키에서 jwt 삭제
     */
    @GetMapping
    public String logout(HttpServletResponse res) {
        Cookie cookie = new Cookie(LoginCheck.COOKIE_NAME, "");
        cookie.setPath("/");
        cookie.setMaxAge(0);

        res.addCookie(cookie);

        return "redirect:/login";
    }

//    @GetMapping("main")
//    public void mainPage(Model model, @LoginUser String id) {
//        log.info("로그인 아이디 : {}", id);
//    }

}
