# jwt 및 oauth2 (kafka 연동 및 온라인 컴파일러 테스트)

### Technologies used:

• JAVA 11    
• Spring Boot 2.7.4    
• Spring Security (Security)   
• MySql     
• WebSocket     
• Swagger 3.0     
• Oauth 2.0     
• Stomp     
• JPA (ORM)   
• JUnit (Test)    
• QueryDSL   
• Kafka   

### JPA & QueryDSL (ORM)   
객체 중심 domain 설계 및 반복적인 CRUD 작업을 대체해 비즈니스 로직에 집중한다.   
• JPA : 반복적인 CRUD 작업을 대체해 간단히 DB에서 데이터를 조회한다.    
• QueryDSL : JPA로 해결할 수 없는 SQL은 QueryDSL로 작성한다.

### Spring Security (Security)

Security 설정을 추가해 인가된 사용자만 특정 URL에 접근할 수 있도록 제한한다. 
Anonymous 가 접근할 수 있어야 하는 API는 permitAll()을 선언했습니다.
또한 ROLE_USER, ROLE_ADMIN, ROLE_TUTOR 권한 별 URL 제한했습니다.


### WebSocket & Stomp

실시간 챗봇과 페어프로그래밍에 WebSocket과 Stomp를 이용하여 실시간 통신기능을 개발한다.

### Kafka(Message Queue)

소켓 통신의 동시성과 데이터 안정성을 위해 메시지 큐를 이용해 관리한다.
