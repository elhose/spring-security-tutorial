package com.js.securitytutorial.student;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/students")
public class StudentManagementController {

    private static List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Michael Scott"),
            new Student(2, "Jim Halpert"),
            new Student(3, "Pam Beasly"),
            new Student(4, "Dwight K. Schrute"));

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMIN_TRAINEE')")
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('course:write')")
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("ADDING STUDENT: " + student);
    }

    @DeleteMapping("{studentId}")
    @PreAuthorize("hasAuthority('course:write')")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("DELETING STUDENT WITH ID: " + studentId);
    }

    @PutMapping("{studentId}")
    @PreAuthorize("hasAuthority('course:write')")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.println("UPDATING STUDENT WITH -> ID: " + studentId + " Student: " + student);
    }
}
