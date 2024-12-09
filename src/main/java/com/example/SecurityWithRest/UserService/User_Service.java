package com.example.SecurityWithRest.UserService;

import com.example.SecurityWithRest.Model.User;
import com.example.SecurityWithRest.Repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;
@Component
public class User_Service {
    @Autowired
    @Lazy
    private PasswordEncoder passwordEncoder_1;
    @Autowired
    private UserRepository userRepository;

    public User createUser(User user){
        if (passwordEncoder_1 == null){
            throw new IllegalStateException("PasswordEncoder is not properly initialized");
        }
        String encodePassword = passwordEncoder_1.encode(user.getPassword());
        user.setPassword(encodePassword);
        return userRepository.save(user);
    }
    public  User login(String username, String password)throws Exception{
        Optional<User> userOptional = Optional.ofNullable(userRepository.findByUsername(username));
        if (userOptional.isPresent()){
            User user = userOptional.get();
            if (passwordEncoder_1.matches(password, user.getPassword())){
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(user,null,null);
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                return user;
            }
            else {
                throw new Exception("Invalid Credentials");
            }
        }else {
            throw new Exception("User not Found");
        }
    }
    public User FindByUserName(String username){
        return userRepository.findByUsername(username);
    }
    public User updateUserRole(Long id, String newRole)throws Exception{
        Optional<User> userOptional = userRepository.findById(id);
        if (userOptional.isPresent()){
            User user = userOptional.get();
            user.setRole(newRole);
            return userRepository.save(user);
        }else {
            throw new Exception("User ID is not found");
        }
    }
    public void logout(){
        SecurityContextHolder.clearContext();
    }

}
