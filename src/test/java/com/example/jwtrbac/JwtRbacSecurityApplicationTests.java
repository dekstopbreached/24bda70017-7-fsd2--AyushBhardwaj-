package com.example.jwtrbac;

import com.example.jwtrbac.dto.AuthRequest;
import com.example.jwtrbac.dto.RegisterRequest;
import com.example.jwtrbac.model.Role;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class JwtRbacSecurityApplicationTests {

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private ObjectMapper objectMapper;

	@Test
	@DisplayName("1. Public health check endpoint should be accessible without authentication")
	void testPublicEndpointAccessibleWithoutToken() throws Exception {
		mockMvc.perform(get("/api/public/health"))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data.status").value("UP"));
	}

	@Test
	@DisplayName("2. Protected user endpoint should return 401 Unauthorized when no token is supplied")
	void testProtectedEndpointWithoutTokenReturns401() throws Exception {
		mockMvc.perform(get("/api/user/profile"))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.status").value(401))
				.andExpect(jsonPath("$.error").value("Unauthorized"));
	}

	@Test
	@DisplayName("3. Login with wrong credentials should return 401 Unauthorized")
	void testLoginWithBadCredentialsReturns401() throws Exception {
		AuthRequest badRequest = new AuthRequest("user", "wrongpassword");

		mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(badRequest)))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.success").value(false));
	}

	@Test
	@DisplayName("4. Login with valid user credentials should return valid JWT token")
	void testLoginSuccessReturnsJwt() throws Exception {
		AuthRequest loginRequest = new AuthRequest("user", "user123");

		MvcResult result = mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(loginRequest)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data.token").isNotEmpty())
				.andExpect(jsonPath("$.data.username").value("user"))
				.andExpect(jsonPath("$.data.roles[0]").value("ROLE_USER"))
				.andReturn();

		String token = extractToken(result);
		assertThat(token).isNotBlank();
	}

	@Test
	@DisplayName("5. User role can access /api/user/profile with Bearer token")
	void testUserAccessUserProfileSuccess() throws Exception {
		String userToken = obtainJwtToken("user", "user123");

		mockMvc.perform(get("/api/user/profile")
						.header("Authorization", "Bearer " + userToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data.username").value("user"));
	}

	@Test
	@DisplayName("6. User role attempting /api/admin/users should be blocked with 403 Forbidden")
	void testUserAccessingAdminEndpointReturns403() throws Exception {
		String userToken = obtainJwtToken("user", "user123");

		mockMvc.perform(get("/api/admin/users")
						.header("Authorization", "Bearer " + userToken))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.status").value(403))
				.andExpect(jsonPath("$.error").value("Forbidden"));
	}

	@Test
	@DisplayName("7. Admin role can access /api/admin/users and /api/user/profile")
	void testAdminAccessAdminAndUserEndpointsSuccess() throws Exception {
		String adminToken = obtainJwtToken("admin", "admin123");

		// Access Admin endpoint
		mockMvc.perform(get("/api/admin/users")
						.header("Authorization", "Bearer " + adminToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data").isArray());

		// Access User endpoint
		mockMvc.perform(get("/api/user/profile")
						.header("Authorization", "Bearer " + adminToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data.username").value("admin"));
	}

	@Test
	@DisplayName("8. Moderator role can access /api/mod/reports, but is forbidden from /api/admin/users")
	void testModeratorRbacRestrictions() throws Exception {
		String modToken = obtainJwtToken("moderator", "mod123");

		// Moderator accesses Moderator endpoint -> 200 OK
		mockMvc.perform(get("/api/mod/reports")
						.header("Authorization", "Bearer " + modToken))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.success").value(true));

		// Moderator accesses Admin endpoint -> 403 Forbidden
		mockMvc.perform(get("/api/admin/users")
						.header("Authorization", "Bearer " + modToken))
				.andExpect(status().isForbidden())
				.andExpect(jsonPath("$.status").value(403));
	}

	@Test
	@DisplayName("9. Register new user dynamically and authenticate")
	void testDynamicUserRegistrationAndLogin() throws Exception {
		RegisterRequest regRequest = new RegisterRequest(
				"alice_test",
				"password123",
				"Alice Test",
				"alice@test.com",
				Set.of(Role.ROLE_USER)
		);

		mockMvc.perform(post("/api/auth/register")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(regRequest)))
				.andExpect(status().isCreated())
				.andExpect(jsonPath("$.success").value(true))
				.andExpect(jsonPath("$.data.username").value("alice_test"));

		// Login with newly created user
		String token = obtainJwtToken("alice_test", "password123");
		assertThat(token).isNotBlank();

		// Access user profile with newly created user
		mockMvc.perform(get("/api/user/profile")
						.header("Authorization", "Bearer " + token))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.data.username").value("alice_test"));
	}

	private String obtainJwtToken(String username, String password) throws Exception {
		AuthRequest request = new AuthRequest(username, password);
		MvcResult result = mockMvc.perform(post("/api/auth/login")
						.contentType(MediaType.APPLICATION_JSON)
						.content(objectMapper.writeValueAsString(request)))
				.andExpect(status().isOk())
				.andReturn();
		return extractToken(result);
	}

	private String extractToken(MvcResult result) throws Exception {
		String json = result.getResponse().getContentAsString();
		JsonNode root = objectMapper.readTree(json);
		return root.path("data").path("token").asText();
	}
}
