# SpringSecurity JWT

- Security + JWT를 활용한 로그인 구현


## Spring Initializr
- Lombok
- Spring Web
- Spring Security
- Spring Data JPA
- MySQL Driver

## 목표
- 로그인 성공 시, Access/Refresh에 해당하는 다중 토큰을 발급한다.
- 각각의 토큰은 사용처에 따라 서로 다른 저장소에 발급한다.
- Access : 헤더에 발급 후 front에서 로컬 스토리지에 저장한다.
- Refresh : Server 저장소에 저장한다.

## 참고문서
https://jwt.io/ </br>
https://docs.spring.io/spring-security/reference/servlet/architecture.html

<hr>


## 1. 정의
JSON Web Token의 약자로, 서버 세션이 유저 정보를 저장하는 세션 방식과 달리 토큰 생성 method를 통해 토큰을 생성하여 응답한다.

## 2. 구성
{Header}.{Payload}.{Signature}

**Header** : JWT임을 명시하고, 사용된 암호화 알고리즘의 정보 <br>
**Payload** : 클라이언트에 대한 정보 <br>
**Signature** : header에서 지정한 알고리즘과 secret key

## 3. 특징
**1. stateless**

## 4.과정
**로그인**
![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/9ea93dc0-56d5-486a-b829-ccf699954d44/fc44dcd7-6f1b-457e-a5bf-2bd9bfe6320d/image.png)

## 5. 고찰
각 토큰 사용처에 따라 알맞은 저장소를 설정해야한다.
- 로컬 스토리지 : XSS 공격에 취약
- httpOnly 쿠키 : CSRF 공격에 취약

-> Refresh token을 서버 측 저장소에 저장하였다.

해당 프로젝트에서는 MySQL DB에 저장하였으나, 조회 성능 향상과 TTL 설정을 위해 Redis에 저장하는 것이 좋다는 것을 확인하였다.
