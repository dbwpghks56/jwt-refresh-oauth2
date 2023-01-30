package com.example.jwt.refresh.study.jwt.example.web;

import com.example.jwt.refresh.study.jwt.example.service.WasmTestService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class TestController {
    private final WasmTestService wasmTestService;
    @GetMapping
    public ResponseEntity<String> test() {
        return new ResponseEntity<>("Hello", HttpStatus.OK);
    }

    @GetMapping("/wasm")
    public ResponseEntity<String> wasm() {
        return new ResponseEntity<>(wasmTestService.testWasm(), HttpStatus.OK);
    }
}
