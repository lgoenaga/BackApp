package springjwt.service;

import org.springframework.stereotype.Service;
import springjwt.models.ERole;
import springjwt.models.Role;
import springjwt.payload.request.SignupRequest;

import java.util.Set;

import springjwt.repository.RoleRepository;


@Service
public class RolesService {

    final
    RoleRepository roleRepository;

    private static final String ERROR_ROLE = "Error: Role is not found.";

    public RolesService(RoleRepository roleRepository) {
        this.roleRepository = roleRepository;
    }

    public void getRol(SignupRequest signUpRequest, Set<Role> roles) {
        Set<String> strRoles = signUpRequest.getRole();

        if (strRoles == null) {
            Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException(ERROR_ROLE));
            roles.add(userRole);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin" -> {
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException(ERROR_ROLE));
                        roles.add(adminRole);
                    }
                    case "mod" -> {
                        Role modRole = roleRepository.findByName(ERole.ROLE_MODERATOR)
                                .orElseThrow(() -> new RuntimeException(ERROR_ROLE));
                        roles.add(modRole);
                    }
                    default -> {
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException(ERROR_ROLE));
                        roles.add(userRole);
                    }
                }
            });
        }

    }


}
