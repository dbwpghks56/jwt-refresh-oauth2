package com.example.jwt.refresh.study.jwt.auth.web;

import com.example.jwt.refresh.study.jwt.auth.dto.request.AccessTokenRefreshRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.ApiTest;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignInRequestDto;
import com.example.jwt.refresh.study.jwt.auth.dto.request.SignUpRequestDto;
import com.example.jwt.refresh.study.jwt.auth.service.AuthService;
import com.example.jwt.refresh.study.jwt.boot.exception.RestException;
import com.example.jwt.refresh.study.jwt.boot.util.JwtUtils;
import com.example.jwt.refresh.study.jwt.example.service.WasmTestService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.*;
import okio.ByteString;
import org.hibernate.type.UUIDCharType;
import org.json.JSONObject;
import org.python.antlr.ast.While;
import org.python.util.PythonInterpreter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.bind.annotation.RequestBody;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.rmi.RemoteException;
import java.util.Map;
import java.util.Scanner;
import java.util.UUID;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {
    public static final String FILE_PATH = "C:\\Users\\wpghk\\Downloads\\jwtrefresh-91d0bc1cde9b278d3d7f7e4c640c9fa57893df1f\\study.jwt\\src\\main\\resources";
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

    @PostMapping("/process/python")
    public ResponseEntity<String> pyScript(@RequestBody(required = false) String pyScript) throws IOException {
        String pyName = UUID.randomUUID() + ".py";

        File pyFile = new File(FILE_PATH + "\\" + pyName);

        if(!pyFile.exists()) {
            pyFile.createNewFile();
        }

        BufferedWriter pyCode = new BufferedWriter(new FileWriter(pyFile, true));

        pyCode.write(pyScript);

        pyCode.flush();
        pyCode.close();

        if(pyFile.exists()) {
            ProcessBuilder pyRun = new ProcessBuilder();
            pyRun.directory(new File(FILE_PATH));

            String result = returnProcess("python", pyName, pyRun).toString();

            pyFile.delete();

            return new ResponseEntity<>(result,HttpStatus.OK);
        }

        throw new RestException(HttpStatus.BAD_REQUEST, "파일이 만들어지지 않았습니다.");
    }

    public StringBuffer returnProcess(String command, String processName, ProcessBuilder processCover) throws IOException {
        processCover.command(command, processName);

        Process classRun = processCover.start();

        BufferedReader resultReader = new BufferedReader(new InputStreamReader(classRun.getInputStream()));

        StringBuffer resultLine = new StringBuffer();
        String result = null;
        while ((result = resultReader.readLine()) != null) {
            resultLine.append(result).append("\n");
        }

        if (classRun != null) {
            classRun.destroy();
        }

        return resultLine;
    }

    @PostMapping("/process/java")
    public ResponseEntity<String> processss(@RequestBody(required = false) String javaCode) throws IOException, InterruptedException {
        String codeClassName = UUID.randomUUID().toString().replace("-", "");

        // 자바의 경우 클래스 이름이 수로 시작되면 안 되기 때문에 확인을 하고 수로 시작하게 되면 다시 할당해준다.
        while(Character.isDigit(codeClassName.charAt(0))) {
            codeClassName = UUID.randomUUID().toString().replace("-", "");
        }

        javaCode = javaCode.replace(javaCode.split(" ")[2], codeClassName);
        log.info(javaCode);

        String javaDotJava =  codeClassName + ".java";

        File javaFile = new File(FILE_PATH +"\\" + javaDotJava);

        if(!javaFile.exists()) {
            javaFile.createNewFile();
        }

        BufferedWriter jCode = new BufferedWriter(new FileWriter(javaFile, true));

        jCode.write(javaCode);

        jCode.flush();
        jCode.close();

        if(javaFile.exists()) {
            ProcessBuilder javaRun = new ProcessBuilder();

            javaRun.directory(new File(FILE_PATH));
            javaRun.command("javac", javaDotJava);
            javaRun.start();

            StringBuffer doneResult = returnProcess("java", "Test", javaRun);

            File javaClass = new File(FILE_PATH +"\\" + codeClassName + ".class");
//            Thread.sleep(3000);

            while ((doneResult.toString().contains("done"))) {

                if (javaClass.exists()) {
                    log.info(codeClassName);
                    String resultLine = returnProcess("java", codeClassName, javaRun).toString();

                    javaFile.delete();
                    javaClass.delete();

                    return new ResponseEntity<>(resultLine, HttpStatus.OK);
                }
            }

            javaFile.delete();
            throw new RestException(HttpStatus.BAD_REQUEST, "컴파일된 파일이 만들어지지 않았습니다.");
        } else {
            throw new RestException(HttpStatus.BAD_REQUEST, "파일이 만들어지지 않았습니다.");
        }

    }
}
