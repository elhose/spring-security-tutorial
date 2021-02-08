package com.js.securitytutorial.student;

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
    public List<Student> getAllStudents() {
        return STUDENTS;
    }

    @PostMapping
    public void registerNewStudent(@RequestBody Student student) {
        System.out.println("ADDING STUDENT: " + student);
    }

    @DeleteMapping("{studentId}")
    public void deleteStudent(@PathVariable("studentId") Integer studentId) {
        System.out.println("DELETING STUDENT WITH ID: " + studentId);
    }

    @PutMapping("{studentId}")
    public void updateStudent(@PathVariable("studentId") Integer studentId, @RequestBody Student student) {
        System.out.println("UPDATING STUDENT WITH -> ID: " + studentId + " Student: " + student);
    }
}
