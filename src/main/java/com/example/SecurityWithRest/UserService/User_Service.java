package com.example.SecurityWithRest.UserService;

import com.example.SecurityWithRest.Model.User;
import com.example.SecurityWithRest.Repo.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.Optional;
@Component
public class User_Service {
    private PasswordEncoder passwordEncoder;
    private UserRepository userRepository;

    public User createUser(User user){
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }
    public  User login(String username, String password)throws Exception{
        Optional<User> userOptional = Optional.ofNullable(userRepository.findByUsername(username));
        if (userOptional.isPresent()){
            User user = userOptional.get();
            if (passwordEncoder.matches(password, user.getPassword())){
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
