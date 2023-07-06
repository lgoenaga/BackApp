package springjwt.service;



import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import springjwt.models.Role;
import springjwt.models.User;
import springjwt.payload.request.SignupRequest;
import springjwt.payload.response.MessageResponse;
import springjwt.repository.UserRepository;

import java.util.HashSet;
import java.util.Set;

@Service
public class UserService {

    final
    PasswordEncoder encoder;

    final
    RolesService rolesService;


    final
    UserRepository userRepository;

    private static final String ERROR_USERNAME = "Error: Username is already taken!";
    private static final String ERROR_EMAIL = "Error: Email is already in use!";
    private static final String USER_SUCCESS = "User registered successfully!";

    public UserService(PasswordEncoder encoder, RolesService rolesService, UserRepository userRepository) {
        this.encoder = encoder;
        this.rolesService = rolesService;
        this.userRepository = userRepository;
    }

    public ResponseEntity<MessageResponse> createUser(SignupRequest signUpRequest) {
        if (Boolean.TRUE.equals(userRepository.existsByUsername(signUpRequest.getUsername()))) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse(ERROR_USERNAME));
        }

        if (Boolean.TRUE.equals(userRepository.existsByEmail(signUpRequest.getEmail()))) {
            return ResponseEntity
                    .badRequest()
                    .body(new MessageResponse(ERROR_EMAIL));
        }

        // Create new user's account
        User user = new User(signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));


        Set<Role> roles = new HashSet<>();
        rolesService.getRol(signUpRequest, roles);

        user.setRoles(roles);
        userRepository.save(user);

        return ResponseEntity.ok(new MessageResponse(USER_SUCCESS));
    }



}
