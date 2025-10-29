# Mobile Security evaluation assignment guidelines

## Overview
This document contains all information about the evaluation assignment for the course Mobile Security.
Read this document carefully for the assignment requirements, deliverables and rules.

## Group
This is a group project in groups of maximum 4 students per group. The groups are assigned using LEHO with self sign-up in the group.

**IMPORTANT**: 
- The **deadline** of self sign-up is *02/10/2025 at 9:00am*. After the deadline the lecturers will enrol you in a group of our choosing.
- Do **not** enrol yourself in a group without discussing it with fellow students.

## Assignment description
The goal is to create an Android application with vulnerabilities to pentest in an Pentesting Mobile environment.

The application has the following functionality:
- [ ] At least 2 UI screens
- [ ] 2 requests to an API
- [ ] Bonus: use SSL pinning
- [ ] Intercept and modify the request -> doesn't affect the secure application
- [ ] Second request is an IDOR -> intercept affects the application
- [ ] Connection to a local database
- [ ] Not vulnerable for SQLi -> use Room databases
- [ ] Implement functionality that stores data securely on the device. For example via the camera or microphone
- [ ] Store credentials using an unsafe encryption
- [ ] Malware inserted in the application
- [ ] Bonus: inject malware using decompile & recompile
- [ ] Functionality that can be bypassed using Frida
  - Own written scripts, no defaults provided by the repository
- [ ] Functionality that can be changed using decompiling and recompiling the application
- [ ] Block functionality if the device is rooted
  - Use a Magisk module to hide root on the device for demonstration

The following is not allowed:
- Use of frameworks (for example: Flutter)
- Use of XML views

Use everything seen in the course, exceptions are possible with approval of the lecturers.

### Example application
- Screen 1: Overview screen with connection to database for products or API request for products
- Screen 2: Detail screen with request to API or database connection to get more information
- Malware: sending contact information to API, create involuntary pictures, video, screen recording, screenshot, audio recording, GPS data, keylogger, ransomware, ...
  - For bonus points: the written malware is injected in the application.
- Frida: bypass security, become administrator user, in a game never lose. The goal is to overwrite a function from the application in Frida.

## Evaluation
The assignment is 100% of the total grade of this module.

Evaluation is based on the following items:

**PT1**
- Theoretical/insight questions about Mobile Security -> content from the slides & labs

**PT2**
- The Android application, maintained in gitlab
- Setup Android device
- Peer evaluation
- The live demonstration with questions by lecturers.

*!Omission or significantly incomplete implementation of a single deliverable will result in a failing score for the entire module!*

Example questions during the demonstration:
- Explain the Frida script
- Explain parts of the code in Kotlin and/or Smali
- Intercept a request in Burp Suite
- Show a dynamic analysis of the application
- Decompile/recompile the application

Example theoretical questions:
- What is static analysis?
- Explain this adb command `adb root`
- Give an example of Improper credential usage
- What does the following code do?
```kotlin
modifier = Modifier
  .size(40.dp)
  .clip(CircleShape)
)
```
A mock exam will be provided in the final lesson.

### Scoring calculation
- PT1: 15%
- PT2: 85%
  - Application: 45%
  - Device: 10%
  - Peer evaluation: 5%
  - Demonstration & individual questions: 25%
    - Questions can be about the project and **individual** lab exercises

#### Factors influencing the final score
There are many factors weighing on the final score for this module. Each part of the assignment is scored according to specific criteria. This score can be influenced by intermediate as well as end results of a certain portion.

A group score will be determined according to the principles listed above. From this group score, the individual score will deviate in positive or negative manner depending on the following factors.

**Demonstration & questions**:
This is an individually graded component. Each group member will be scored individually for his performance during the presentation, measured on a number of factors.

**Conduct and contribution**
Your general conduct and contribution throughout the semester is monitored by the lecturers as well as assessed by your peers. Deviations, positive or negative, will impact your final individual score.

Inappropriate conduct may be a reason for immediate group exclusion (resulting in zero score for this module). The lecturers may come to this conclusion at his/her discretion.

## Practical
*Deadlines*

Exam period: Every lesson is possible to ask for evaluation, keep in mind that it is not possible to redo the assignment in this exam period and there is only 1 moment for evaluation per student.

The theoretical part is a LEHO (LDB) quiz only during the exam period.