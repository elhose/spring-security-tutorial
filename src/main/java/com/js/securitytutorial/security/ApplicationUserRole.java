package com.js.securitytutorial.security;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static com.js.securitytutorial.security.ApplicationUserPermission.*;

public enum ApplicationUserRole {
    STUDENT(new HashSet<>(Collections.emptySet())),
    ADMIN(new HashSet<>(Arrays.asList(COURSE_READ, COURSE_WRITE, STUDENT_READ, STUDENT_WRITE)));

    private final Set<ApplicationUserPermission> permissions;

    ApplicationUserRole(Set<ApplicationUserPermission> permissions) {
        this.permissions = permissions;
    }

    public Set<ApplicationUserPermission> getPermissions() {
        return permissions;
    }
}
