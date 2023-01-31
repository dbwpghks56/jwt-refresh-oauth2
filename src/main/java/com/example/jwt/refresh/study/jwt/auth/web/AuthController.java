package com.example.jwt.refresh.study.jwt.auth.web;

import com.example.jwt.refresh.study.jwt.auth.dto.request.AccessTokenRefreshRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignInRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignUpRequestDto;
import com.example.jwt.refresh.study.jwt.auth.service.AuthService;
import com.example.jwt.refresh.study.jwt.boot.util.JwtUtils;
import com.example.jwt.refresh.study.jwt.example.service.WasmTestService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.python.util.PythonInterpreter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
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
        String randoom = UUID.randomUUID() + ".py";

        String path2 = "C:\\Users\\wpghk\\Downloads\\jwtrefresh-91d0bc1cde9b278d3d7f7e4c640c9fa57893df1f\\study.jwt\\src\\main\\resources";
        String filePath = "C:\\Users\\wpghk\\Downloads\\jwtrefresh-91d0bc1cde9b278d3d7f7e4c640c9fa57893df1f\\study.jwt\\src\\main\\resources\\"+randoom;

        File file = new File(filePath);
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
            builder.command("python", randoom);

            Process process = builder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

            StringBuffer line = new StringBuffer();
            String mola = null;
            while((mola = reader.readLine()) != null) {
                line.append(mola+"\n");
                log.info(line.toString());
            }

            if(process != null) {
                process.destroy();
            }
            file.delete();
            return new ResponseEntity<>(line.toString(), HttpStatus.OK);
        } else {
            return null;
        }

    }
}
