package com.example.SecurityWithRest.Controller;

import com.example.SecurityWithRest.Model.User;
import com.example.SecurityWithRest.UserService.User_Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
public class UserController {
    @Autowired
    private User_Service userService;

    @PostMapping("/create")
    public ResponseEntity<String> createUser(@RequestBody User user){
        userService.createUser(user);
        return ResponseEntity.ok("User created Successfully");
    }
    @GetMapping("/me")
    public String getCurrentUser() {
        return "Current User: " + SecurityContextHolder.getContext().getAuthentication().getName();
    }
    @PutMapping("/update{username}/role")
    public Object updateUserRole(@PathVariable Long id, @RequestParam String role)throws  Exception{
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        if(principal instanceof User){
            User loggedInUser = (User) principal;
            if ("ADMIN".equals(loggedInUser.getRole())){
                if (role.equals("ADMIN") || role.equals("USER")){
                    try {
                        userService.updateUserRole(id,role);
                        return ResponseEntity.ok("User role update sucessfully");
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }

                }else {
                    return ResponseEntity.badRequest();
                }
            }else {
                return ResponseEntity.badRequest();
            }
        }else {
            return ResponseEntity.badRequest();
        }
    }
}
