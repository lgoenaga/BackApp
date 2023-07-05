package springjwt.controllers;

import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

import org.springframework.security.crypto.password.PasswordEncoder;

import springjwt.exceptions.UserNotFoundException;
import springjwt.models.Role;
import springjwt.models.User;
import springjwt.payload.request.SignupRequest;
import springjwt.payload.response.MessageResponse;
import springjwt.repository.RoleRepository;

import springjwt.repository.UserRepository;
import springjwt.service.RolesService;
import springjwt.service.UserService;

import java.util.*;


@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/users")
public class UserController {

    final
    UserRepository userRepository;

    final
    PasswordEncoder encoder;

    final
    RoleRepository roleRepository;

    final
    RolesService rolesService;

    final
    UserService userService;
    private static final String ERROR_USERNAME = "Error: Username is already taken!";
    private static final String ERROR_EMAIL = "Error: Email is already in use!";
    private static final String USER_SUCCESS = "User registered successfully!";

    public UserController(UserService userService, RolesService rolesService, UserRepository userRepository, PasswordEncoder encoder, RoleRepository roleRepository) {
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.roleRepository = roleRepository;
        this.rolesService = rolesService;
        this.userService = userService;
    }

    @GetMapping("/all")
    public String allAccess() {
        return "Public Content.";
    }

    @GetMapping("/user")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public String userAccess() {
        return "User Content.";
    }

    @GetMapping("/mod")
    @PreAuthorize("hasRole('MODERATOR')")
    public String moderatorAccess() {
        return "Moderator Board.";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ADMIN')")
    public String adminAccess() {
        return "Admin Board.";
    }

    @GetMapping("")
    @PreAuthorize("hasRole('USER') or hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<List<User>> getAllUsers() {

        List<User> users = userRepository.findAll();
        return ResponseEntity.ok(users);
    }
    @PostMapping("")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<MessageResponse> createUser(@Valid @RequestBody SignupRequest signUpRequest) {
        userService.createUser(signUpRequest);
        return ResponseEntity.ok(new MessageResponse(USER_SUCCESS));
    }

    @DeleteMapping("/{userId}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<String> deleteUser(@PathVariable Long userId){
        if(!userRepository.existsById(userId)){
            throw new UserNotFoundException(userId);
        }
        userRepository.deleteById(userId);
        return ResponseEntity.ok("User deleted successfully!");
    }

    @PutMapping("/{userId}")
    @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
    public ResponseEntity<MessageResponse> updateUser(@PathVariable Long userId, @RequestBody SignupRequest signUpRequest) {
        if(!userRepository.existsById(userId)){
            throw new UserNotFoundException(userId);
        }

        User existUser = userRepository.findById(userId).orElseThrow(() -> new UserNotFoundException(userId));

        if (!Objects.equals(existUser.getUsername(), signUpRequest.getUsername()) && Boolean.TRUE.equals((userRepository.existsByUsername(signUpRequest.getUsername())))) {
                return ResponseEntity
                        .badRequest()
                        .body(new MessageResponse(ERROR_USERNAME));

        }

        if (!Objects.equals(existUser.getEmail(), signUpRequest.getEmail()) && Boolean.TRUE.equals((userRepository.existsByEmail(signUpRequest.getEmail())))) {
                return ResponseEntity
                        .badRequest()
                        .body(new MessageResponse(ERROR_EMAIL));

        }

        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        String generatedPassword = passwordEncoder.encode(signUpRequest.getPassword());
        existUser.setPassword(generatedPassword);

        existUser.setEmail(signUpRequest.getEmail());
        existUser.setUsername(signUpRequest.getUsername());

        Set<Role> roles = new HashSet<>();

        rolesService.getRol(signUpRequest, roles);

        existUser.setRoles(roles);

        userRepository.save(existUser);
        return ResponseEntity.ok(new MessageResponse(USER_SUCCESS));

    }


}
