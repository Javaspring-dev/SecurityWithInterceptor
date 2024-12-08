package com.example.SecurityWithRest.interceptor;

import com.example.SecurityWithRest.Model.User;
import com.example.SecurityWithRest.UserService.User_Service;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.List;
import java.util.Optional;

@Component
public class CustomInterceptor implements HandlerInterceptor {
    private User_Service userService;
    private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();

    public CustomInterceptor(User_Service userService) {
        this.userService=userService;
    }


    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response,Object handler)throws Exception{
        String username = request.getHeader("X-user");
        String password = request.getHeader("X-password");
        if (username !=null && password !=null){
            Optional<User> optionalUser = Optional.ofNullable(userService.FindByUserName(username));
            if(optionalUser.isPresent()){
                User user = optionalUser.get(); // User model
                if (passwordEncoder.matches(password, user.getPassword())){
                    SecurityContextHolder.getContext().setAuthentication(new UsernamePasswordAuthenticationToken(user.getUsername(), null,List.of(()-> user.getRole())));
                    return true;
                }
            }
        }
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.getWriter().write("Invalid credentials");
        return false;
    }
}
