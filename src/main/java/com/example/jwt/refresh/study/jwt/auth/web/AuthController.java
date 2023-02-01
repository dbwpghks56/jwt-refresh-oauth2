package com.example.jwt.refresh.study.jwt.auth.web;

import com.example.jwt.refresh.study.jwt.auth.dto.request.AccessTokenRefreshRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignInRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignUpRequestDto;
import com.example.jwt.refresh.study.jwt.auth.service.AuthService;
import com.example.jwt.refresh.study.jwt.boot.util.JwtUtils;
import com.example.jwt.refresh.study.jwt.example.service.WasmTestService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.python.antlr.ast.While;
import org.python.util.PythonInterpreter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.util.Scanner;
import java.util.UUID;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;
    private final JwtUtils jwtUtils;
    private final WasmTestService wasmTestService;

    @GetMapping("wasm")
    public ResponseEntity<String> wasmTest() {
        return new ResponseEntity<>(wasmTestService.testWasm(), HttpStatus.OK);
    }

    @PostMapping("/signin")
    public ResponseEntity<?> signIn(@RequestBody SignInRequestDto signInRequestDto) throws Exception {
        return ResponseEntity.ok(authService.signIn(signInRequestDto));
    }

    @PostMapping("/signout")
    public ResponseEntity<?> signOut(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) throws Exception {
        return new ResponseEntity<>(authService.signOut(authorization), HttpStatus.OK);
    }

    @PostMapping("/signup/common")
    public ResponseEntity<?> signUpCommon(@RequestBody SignUpRequestDto signUpRequestDto) throws Exception {
        return new ResponseEntity<>(authService.signUpCommon(signUpRequestDto), HttpStatus.CREATED);
    }

    @PostMapping("getusername")
    public ResponseEntity<?> getUserName(@RequestHeader(value = HttpHeaders.AUTHORIZATION, required = false) String authorization) throws Exception {
        return new ResponseEntity<>(authService.getUserName(authorization), HttpStatus.OK);
    }

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/signup/admin")
    public ResponseEntity<?> signUpAdmin(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorization,
                                         @RequestBody SignUpRequestDto signUpRequestDto) throws Exception {
        return new ResponseEntity<>(authService.signUpAdmin(signUpRequestDto), HttpStatus.CREATED);
    }

    @PostMapping("/token/refresh")
    public ResponseEntity<?> accessTokenRefresh(@RequestBody AccessTokenRefreshRequestDto accessTokenRefreshRequestDto) {
        return new ResponseEntity<>(authService.accessTokenRefresh(accessTokenRefreshRequestDto), HttpStatus.OK);
    }

    @GetMapping("/kakao")
    public ResponseEntity<?> signInKakao(@RequestParam String code, HttpServletRequest request) {

        return new ResponseEntity<>(authService.oauthLogin(code, request.getServletPath()), HttpStatus.OK);
    }

    @GetMapping("/google")
    public ResponseEntity<?> signInGoogle(@RequestParam String code, HttpServletRequest request) {
        return new ResponseEntity<>(authService.oauthLogin(code, request.getServletPath()), HttpStatus.OK);
    }

    @GetMapping("/naver")
    public ResponseEntity<?> signinNaver(@RequestParam String code, HttpServletRequest request) {
        return new ResponseEntity<>(authService.oauthLogin(code,request.getServletPath()), HttpStatus.OK);
    }

    @GetMapping("/python")
    public ResponseEntity<?> runPython(@RequestParam String pyScript) {
        try(PythonInterpreter pythonInterpreter = new PythonInterpreter()) {
            pythonInterpreter.exec(pyScript);

            return new ResponseEntity<>("", HttpStatus.OK);
        }

    }

    @PostMapping("/process")
    public ResponseEntity<String> processss(@RequestBody(required = false) String pyScript) throws IOException, InterruptedException {
        String randoom =  "Test3.java";
        String randoom2 = randoom.replace(".java", "");

        String path2 = "C:\\Users\\wpghk\\Downloads\\jwtrefresh-91d0bc1cde9b278d3d7f7e4c640c9fa57893df1f\\study.jwt\\src\\main\\resources";

        File file = new File(path2 +"\\" + randoom);
        if(!file.exists()) {
            file.createNewFile();
        }

        BufferedWriter writer = new BufferedWriter(new FileWriter(file, true));

        writer.write(pyScript);

        writer.flush();
        writer.close();

        if(file.exists()) {
            ProcessBuilder builder = new ProcessBuilder();
            builder.directory(new File(path2));
            builder.command("javac", randoom);
            builder.start();
            builder.command("java", "Test");
            Process process = builder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            StringBuffer ttt = new StringBuffer();
            String mola = null;
            while ((mola = reader.readLine()) != null) {
                ttt.append(mola);
                log.info(ttt.toString());
            }

            if (process != null) {
                process.destroy();
            }

//            Thread.sleep(3000);
            while(!(ttt.equals("done"))) {

                if(new File(path2 +"\\" + "Test3.class").exists()){
                    builder.command("java", "Test3");
                    Process process2 = builder.start();

                    BufferedReader reader2 = new BufferedReader(new InputStreamReader(process2.getInputStream()));

                    StringBuffer line2 = new StringBuffer();
                    String mola2 = null;
                    while ((mola2 = reader2.readLine()) != null) {
                        line2.append(mola2).append("\n");
                    }

                    if (process2 != null) {
                        process2.destroy();
                    }

                    file.delete();
                    new File(path2 +"\\" + "Test3.class").delete();

                    return new ResponseEntity<>(line2.toString(), HttpStatus.OK);
                }
            }
           return null;
        } else {
            return null;
        }

    }
}
