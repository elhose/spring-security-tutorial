package com.js.securitytutorial.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/v1/students")
public class StudentController {

    private static List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Michael Scott"),
            new Student(2, "Jim Halpert"),
            new Student(3, "Pam Beasly"));

    @GetMapping(path = "/{studentId}")
    public Student getStudent(@PathVariable("studentId") Integer studentId) {
        return STUDENTS.stream().filter(student -> student.getId().equals(studentId))
                       .findAny()
                       .orElseThrow(() -> new IllegalStateException("No student with ID: " + studentId));
    }

}
