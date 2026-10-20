# Experiment 7: Secure Backend APIs Using JWT Authentication and Role-Based Authorization

## Aim
To implement secure backend APIs using JWT authentication and role-based authorization.

## Objectives
- To understand JWT-based stateless authentication
- To configure Spring Security for API protection
- To implement authentication filters (`OncePerRequestFilter`)
- To enforce role-based access control using RBAC and method-level security (`@PreAuthorize`)

## Course Outcomes (COs) Mapped
- **CO2 - BT2**: Understand the architecture of Spring Security filter chains and JWT tokens.
- **CO3 - BT3**: Apply stateless authentication mechanisms and filters to protect REST endpoints.
- **CO4 - BT4**: Analyze and enforce fine-grained Role-Based Access Control (RBAC) rules.

---

## Pre-requisites & Software Requirements
- **Java**: JDK 17+ (JDK 21/25 supported)
- **Framework**: Spring Boot 3.4.2
- **Security**: Spring Security 6 & JJWT 0.12.6
- **Testing**: Postman, cURL, JUnit 5 MockMvc test suite, or the built-in Web Portal

---

## Theoretical Architecture & Concepts

### 1. Spring Security Filter Chain
In Spring Security, incoming requests pass through a chain of filters before reaching the controller.
```
HTTP Request
     │
     ▼
[CorsFilter] ──► [JwtAuthenticationFilter] ──► [UsernamePasswordAuthenticationFilter]
                         │
                         ├── Parses 'Authorization: Bearer <token>' header
                         ├── Validates token signature & expiration
                         ├── Loads UserDetails & Authorities
                         └── Sets SecurityContextHolder.getContext().setAuthentication(...)
                                 │
                                 ▼
                     [AuthorizationFilter] (RBAC URL Rules)
                                 │
                                 ▼
                   [DispatcherServlet / Controller]
                                 │
                                 ├── Method-Level Security (@PreAuthorize("hasRole('ADMIN')"))
                                 └── Executes business logic & returns JSON response
```

### 2. JWT (JSON Web Token) Anatomy
Stateless authentication eliminates server-side session state. A JWT consists of three Base64URL-encoded segments separated by dots (`.`):
1. **Header**: Contains the hashing algorithm (`HS384` / `HS256`) and token type (`JWT`).
2. **Payload (Claims)**: Contains standard claims (`sub` = username, `iat` = issued at, `exp` = expiration) and custom claims (`roles` = `["ROLE_ADMIN", "ROLE_USER"]`, `email`, `fullName`).
3. **Signature**: Cryptographic signature generated using HMAC SHA-256/384 with a private server secret key. This guarantees the token cannot be forged or tampered with.

### 3. Role-Based Access Control (RBAC) Matrix

| Endpoint | HTTP Method | Permitted Roles | Description | Unauthenticated (No Token) | Unauthorized Role |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `/api/public/health` | GET | Anyone | Health check | `200 OK` | `200 OK` |
| `/api/public/info` | GET | Anyone | API architecture info | `200 OK` | `200 OK` |
| `/api/auth/login` | POST | Anyone | Authenticates & returns JWT | `200 OK` | `200 OK` |
| `/api/auth/register` | POST | Anyone | Registers user account | `201 Created` | `201 Created` |
| `/api/auth/me` | GET | Authenticated | Current user profile | `401 Unauthorized` | N/A |
| `/api/user/profile` | GET | `ROLE_USER`, `ROLE_ADMIN` | User profile data | `401 Unauthorized` | `403 Forbidden` |
| `/api/user/dashboard` | GET | `ROLE_USER`, `ROLE_ADMIN` | User dashboard | `401 Unauthorized` | `403 Forbidden` |
| `/api/mod/reports` | GET | `ROLE_MODERATOR`, `ROLE_ADMIN` | Moderation queue | `401 Unauthorized` | `403 Forbidden` |
| `/api/admin/users` | GET | `ROLE_ADMIN` only | Lists all users | `401 Unauthorized` | `403 Forbidden` |
| `/api/admin/system-status`| GET | `ROLE_ADMIN` only | JVM & memory stats | `401 Unauthorized` | `403 Forbidden` |
| `/api/admin/grant-role` | POST | `ROLE_ADMIN` only | Elevates user roles | `401 Unauthorized` | `403 Forbidden` |

---

## Pre-loaded Demo Accounts

The application automatically seeds three demo users upon startup with BCrypt password hashing:

| Username | Password | Roles | Access Level |
| :--- | :--- | :--- | :--- |
| **`admin`** | `admin123` | `ROLE_ADMIN`, `ROLE_USER` | Full access across all endpoints |
| **`user`** | `user123` | `ROLE_USER` | Access to user & public endpoints |
| **`moderator`** | `mod123` | `ROLE_MODERATOR` | Access to moderator & public endpoints |

---

## Project Structure

```
FSD 2 Exp7/
├── pom.xml                                      # Maven project configuration with JJWT & Spring Security
├── mvnw & mvnw.cmd                              # Maven Wrapper executables
├── jwt_rbac_postman_collection.json             # Postman Collection for instant import & testing
├── src/
│   ├── main/
│   │   ├── java/com/example/jwtrbac/
│   │   │   ├── JwtRbacSecurityApplication.java  # Main Spring Boot Application entrypoint
│   │   │   ├── controller/
│   │   │   │   ├── AuthController.java          # Login, Register, Current User APIs
│   │   │   │   ├── PublicController.java        # Unprotected public APIs
│   │   │   │   ├── UserController.java          # @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
│   │   │   │   ├── ModeratorController.java     # @PreAuthorize("hasRole('MODERATOR') or hasRole('ADMIN')")
│   │   │   │   └── AdminController.java         # @PreAuthorize("hasRole('ADMIN')")
│   │   │   ├── dto/
│   │   │   │   ├── AuthRequest.java             # Login request payload
│   │   │   │   ├── RegisterRequest.java         # Registration request payload
│   │   │   │   ├── AuthResponse.java            # JWT Bearer token response
│   │   │   │   └── ApiResponse.java             # Standardized API response envelope
│   │   │   ├── exception/
│   │   │   │   └── GlobalExceptionHandler.java  # Handles 401, 403, 400 with clean JSON responses
│   │   │   ├── model/
│   │   │   │   ├── Role.java                    # Enum: ROLE_USER, ROLE_MODERATOR, ROLE_ADMIN
│   │   │   │   └── User.java                    # User domain model
│   │   │   ├── repository/
│   │   │   │   └── UserRepository.java          # Thread-safe in-memory store with demo users
│   │   │   └── security/
│   │   │       ├── AuthConfig.java              # PasswordEncoder Bean (BCrypt)
│   │   │       ├── AuthEntryPointJwt.java       # Returns JSON 401 for unauthenticated requests
│   │   │       ├── CustomAccessDeniedHandler.java # Returns JSON 403 for insufficient roles
│   │   │       ├── CustomUserDetails.java       # Implements Spring Security UserDetails
│   │   │       ├── CustomUserDetailsService.java # Loads user by username from repository
│   │   │       ├── JwtAuthenticationFilter.java # OncePerRequestFilter parsing Bearer token
│   │   │       ├── JwtUtils.java                # Signs, parses, and validates HMAC-SHA JWTs
│   │   │       └── SecurityConfig.java          # Spring Security filter chain & method security
│   │   └── resources/
│   │       ├── application.properties           # Server port, JWT secret & expiration configs
│   │       └── static/
│   │           └── index.html                   # Interactive Web Test Dashboard
│   └── test/
│       └── java/com/example/jwtrbac/
│           └── JwtRbacSecurityApplicationTests.java # 9 Automated MockMvc Integration Tests
```

---

## How to Run the Application

### 1. Start Application using Maven Wrapper:
```powershell
.\mvnw.cmd spring-boot:run
```
Or run the packaged JAR:
```powershell
java -jar target/jwt-rbac-security-0.0.1-SNAPSHOT.jar
```

The application starts on `http://localhost:8080`.

### 2. Interactive Browser Web Portal:
Open your browser and navigate to:
```
http://localhost:8080/
```
Features available in the portal:
- **1-Click Quick Login** for `admin`, `user`, or `moderator`
- **Live JWT Token Inspector** displaying decoded Header and Payload claims
- **Live API Endpoint Tester** with real-time response viewer and HTTP status badge (200 / 401 / 403)
- **On-the-fly User Registration** with custom role selection

### 3. Run Automated Integration Tests:
```powershell
.\mvnw.cmd test
```
All 9 test cases will execute:
1. Public endpoint accessible without token (200 OK)
2. Protected user endpoint returns 401 Unauthorized when no token is supplied
3. Login with wrong credentials returns 401 Unauthorized
4. Login with valid user credentials returns valid JWT token
5. User role accesses `/api/user/profile` successfully (200 OK)
6. User role attempting `/api/admin/users` blocked with 403 Forbidden
7. Admin role accesses `/api/admin/users` and `/api/user/profile` (200 OK)
8. Moderator role accesses `/api/mod/reports` (200 OK) and blocked from `/api/admin/users` (403 Forbidden)
9. Dynamic registration and login workflow verification

---

## Postman / cURL Testing Guide

Import [jwt_rbac_postman_collection.json](file:///c:/Users/Ayush/FSD%202%20Exp7/jwt_rbac_postman_collection.json) into Postman.

### Sample cURL Commands:

#### 1. Login as User:
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"user","password":"user123"}'
```

#### 2. Access Protected User Profile:
```bash
curl -X GET http://localhost:8080/api/user/profile \
  -H "Authorization: Bearer <TOKEN>"
```

#### 3. Attempt Admin Endpoint with User Token (Expect 403 Forbidden):
```bash
curl -X GET http://localhost:8080/api/admin/users \
  -H "Authorization: Bearer <USER_TOKEN>"
```

#### 4. Login as Admin & Access Admin Endpoint (Expect 200 OK):
```bash
# Login Admin
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin123"}'

# Access Admin Users List
curl -X GET http://localhost:8080/api/admin/users \
  -H "Authorization: Bearer <ADMIN_TOKEN>"
```
