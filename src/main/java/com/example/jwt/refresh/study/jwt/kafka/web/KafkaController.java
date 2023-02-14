package com.example.jwt.refresh.study.jwt.kafka.web;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/kafka")
public class KafkaController {
    private final KafkaTemplate<String, String> kafkaTemplate;
    private static final String TOPIC = "my-topic";

    @PostMapping("/publish")
    public String sender(@PathVariable("message")String message, @PathVariable("topic")String topic) {
        kafkaTemplate.send(topic, message);
        return "Published Success";
    }
}
