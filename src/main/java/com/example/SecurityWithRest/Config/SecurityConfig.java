package com.example.SecurityWithRest.Config;

import com.example.SecurityWithRest.UserService.User_Service;
import com.example.SecurityWithRest.filter.CustomFilter;
import com.example.SecurityWithRest.interceptor.CustomInterceptor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.InterceptorRegistration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
@EnableWebSecurity
@Configuration
public class SecurityConfig  {
    private final CustomFilter customFilter;
    public SecurityConfig(CustomFilter customFilter){
        this.customFilter = customFilter;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity)throws Exception{
        httpSecurity.csrf(csrf -> csrf.disable()).authorizeHttpRequests(auth -> auth.requestMatchers("/h2-console/**").permitAll()
                        .requestMatchers("/h2-console/login.do?jsessionid=15d5e4c1f7f0427320fe14709c57c843").permitAll()
                .requestMatchers("/create","/login").permitAll()
                .requestMatchers("/user/**").hasAnyRole("USER","ADMIN")
                .requestMatchers("/update{username}/role").hasRole("ADMIN").anyRequest().authenticated())
                        .addFilterBefore(customFilter, UsernamePasswordAuthenticationFilter.class);
                httpSecurity.addFilterBefore(new CustomFilter(), UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config)throws Exception {
        return config.getAuthenticationManager();
    }
    @Bean
    public PasswordEncoder passwordEncoder_pass(){
        return new BCryptPasswordEncoder();
    }
}
