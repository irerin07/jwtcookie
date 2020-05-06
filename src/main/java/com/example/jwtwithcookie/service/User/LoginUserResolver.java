package com.example.jwtwithcookie.service.User;

import com.example.jwtwithcookie.security.JwtSecurity;
import lombok.RequiredArgsConstructor;
import org.springframework.core.MethodParameter;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class LoginUserResolver implements HandlerMethodArgumentResolver {

    private JwtSecurity jwtSecurity;

    @Override
    public boolean supportsParameter(MethodParameter param) {
        return param.hasParameterAnnotation(LoginUser.class);
    }

    @Override
    public Object resolveArgument(MethodParameter param, ModelAndViewContainer mvc, NativeWebRequest nreq,
                                  WebDataBinderFactory dbf) throws Exception {
        final Map<String, Object> resolved = new HashMap<>();

        HttpServletRequest req = (HttpServletRequest) nreq.getNativeRequest();

        // 쿠키에 토큰이 있는 경우 꺼내서 verify 후 로그인 정보 리턴
        Arrays.stream(req.getCookies()).filter(cookie -> cookie.getName().equals(LoginCheck.COOKIE_NAME))
                .map(Cookie::getValue).findFirst().ifPresent(token -> {
            Map<String, Object> info = jwtSecurity.verify(token);

            // @LoginUser String id, @LoginUser String name
            if (param.getParameterType().isAssignableFrom(String.class)) {
                resolved.put("resolved", info.get(param.getParameterName()));
            }
            // @LoginUser User user
            else if (param.getParameterType().isAssignableFrom(User.class)) {
                User user = User.builder().id((String) info.get("id")).name((String) info.get("name")).build();

                resolved.put("resolved", user);
            }
        });

        return resolved.get("resolved");
    }
}