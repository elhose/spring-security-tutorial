package com.js.securitytutorial.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;

import static com.js.securitytutorial.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao {

    private final PasswordEncoder passwordEncoder;

    public FakeApplicationUserDaoService(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream().filter(applicationUser -> username.equals(applicationUser.getUsername())).findFirst();
    }

    private List<ApplicationUser> getApplicationUsers() {
        return new ArrayList<>(Arrays.asList(
                new ApplicationUser("Jim", passwordEncoder.encode("password"), STUDENT.getGrantedAuthorities(),
                                    true, true, true, true), //ROLE_STUDENT
                new ApplicationUser("Michael", passwordEncoder.encode("password123"), ADMIN.getGrantedAuthorities(),
                                    true, true, true, true), //ROLE_ADMIN
                new ApplicationUser("Dwight", passwordEncoder.encode("password123456"), ADMIN_TRAINEE.getGrantedAuthorities(),
                                    true, true, true, true) //ROLE_ADMINTRAINEE
                                            ));
    }

}
