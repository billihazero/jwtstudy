# SpringSecurity JWT

## 참고문서
https://jwt.io/ </br>
https://docs.spring.io/spring-security/reference/servlet/architecture.html

<hr>

## 1. 정의
JSON Web Token의 약자로, 서버 세션이 유저 정보를 저장하는 세션 방식과 달리 토큰 생성 method를 통해 토큰을 생성하여 응답한다.

## 2. 구성
{Header}.{Payload}.{Signature}

**Header** : JWT임을 명시하고, 사용된 암호화 알고리즘의 정보
**Payload** : 클라이언트에 대한 정보
**Signature** : header에서 지정한 알고리즘과 secret key

## 3. 특징
**1. stateless**

## 4.과정
**로그인**
<img src="![image.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/9ea93dc0-56d5-486a-b829-ccf699954d44/fc44dcd7-6f1b-457e-a5bf-2bd9bfe6320d/image.png)">
