package com.example.jwt.refresh.study.jwt.example.service.impl;

import com.example.jwt.refresh.study.jwt.example.service.WasmTestService;
import de.inetsoftware.jwebassembly.JWebAssembly;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.io.File;

@Slf4j
@Service
@RequiredArgsConstructor
public class WasmTestServiceImpl implements WasmTestService {

    @Override
    public String testWasm() {
        JWebAssembly wasm = new JWebAssembly();
        wasm.addFile(new File("out\\production\\classes\\com\\example\\jwt\\refresh\\study\\jwt\\example\\test\\Add.class"));
        String text = wasm.compileToText();
        log.info("+::" + new File("out\\production\\classes\\com\\example\\jwt\\refresh\\study\\jwt\\example\\test\\Add.class").canRead());
        log.info(":::::" + text);

        return text;
    }
}
