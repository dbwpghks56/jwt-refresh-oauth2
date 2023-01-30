package com.example.jwt.refresh.study.jwt.example.test;

import de.inetsoftware.jwebassembly.api.annotation.Export;

public class Add {
    @Export
    public static int add(int a, int b) {
        return a + b;
    }

    @Export
    public static int minus(int a, int b) {
        return a - b;
    }

}
