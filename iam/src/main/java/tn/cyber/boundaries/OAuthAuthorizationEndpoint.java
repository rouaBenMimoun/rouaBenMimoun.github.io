package tn.cyber.boundaries;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;

import java.io.InputStream;

import tn.cyber.entities.Identity;
import tn.cyber.repositories.IdentityRepository;
import tn.cyber.repositories.TenantRepository;
import tn.cyber.security.Argon2Utils;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import jakarta.ws.rs.core.UriInfo;
import tn.cyber.security.AuthorizationCode;

import static com.mongodb.internal.authentication.AwsCredentialHelper.LOGGER;

@Path("/")
public class OAuthAuthorizationEndpoint {
    public static final String CHALLENGE_RESPONSE_COOKIE_ID = "signInId";
    @Inject
    Argon2Utils argon2Utils;
    @Inject
    TenantRepository tenantRepository;
    @Inject
    IdentityRepository identityRepository;

    @GET
    @Path("/authorize")
    @Produces(MediaType.TEXT_HTML)
    public Response authorize(@Context UriInfo uriInfo) {
        var params = uriInfo.getQueryParameters();
        // 1. Check tenant validation

        var clientId = params.getFirst("client_id");
        if (clientId == null || clientId.isEmpty()) {
            return informUserAboutError("Invalid client_id :" + clientId);
        }
        var tenant = tenantRepository.findByName(clientId);
        if (tenant == null) {
            return informUserAboutError("Invalid client_id with tenant :" + clientId);
        }
        // 2. Client Authorized Grant Type

        if (tenant.getSupportedGrantTypes() != null && !tenant.getSupportedGrantTypes().contains("authorization_code")) {
            return informUserAboutError("Authorization Grant type, authorization_code, is not allowed for this tenant :" + clientId);
        }
        // 3. redirectUri validation

        String redirectUri = params.getFirst("redirect_uri");
        if (tenant.getRedirectUri() != null && !tenant.getRedirectUri().isEmpty()) {
            if (redirectUri != null && !redirectUri.isEmpty() && !tenant.getRedirectUri().equals(redirectUri)) {
                return informUserAboutError("redirect_uri is pre-registred and should match");
            }
            redirectUri = tenant.getRedirectUri();
        } else {
            if (redirectUri == null || redirectUri.isEmpty()) {
                return informUserAboutError("redirect_uri is not pre-registred and should be provided");
            }
        }
        // 4. response_type validation

        String responseType = params.getFirst("response_type");
        if (!"code".equals(responseType) && !"token".equals(responseType)) {
            String error = "invalid_grant :" + responseType + ", response_type params should be code or token:";
            return informUserAboutError(error);
        }
        // 5. check scope

        String requestedScope = params.getFirst("scope");
        if (requestedScope == null || requestedScope.isEmpty()) {
            requestedScope = tenant.getRequiredScopes();
        }
        // 6. Check code_challenge

        String code_challenge = params.getFirst("code_challenge");
        if (code_challenge == null || code_challenge.isEmpty()) {
            return informUserAboutError("Invalid code_challenge :" + code_challenge);
        }
        // 7. code_challenge_method must be S256

        String codeChallengeMethod = params.getFirst("code_challenge_method");
        if(codeChallengeMethod==null || !codeChallengeMethod.equals("S256")){
            String error = "invalid_grant :" + codeChallengeMethod + ", code_challenge_method must be 'S256'";
            return informUserAboutError(error);
        }
        StreamingOutput stream = output -> {
            try (InputStream is = Objects.requireNonNull(getClass().getResource("/Login.html")).openStream()){
                output.write(is.readAllBytes());
            }
        };
        return Response.ok(stream).location(uriInfo.getBaseUri().resolve("/login/authorization"))
                .cookie(new NewCookie.Builder(CHALLENGE_RESPONSE_COOKIE_ID)
                        .httpOnly(true).secure(true).sameSite(NewCookie.SameSite.STRICT).value(tenant.getName()+"#"+requestedScope+"$"+redirectUri).build()).build();
    }

    @POST
    @Path("/login/authorization")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response login(@CookieParam(CHALLENGE_RESPONSE_COOKIE_ID) Cookie cookie,
                          @FormParam("username") String username,
                          @FormParam("password") String password,
                          @Context UriInfo uriInfo) throws Exception {

        try {
            if (cookie == null) {
                LOGGER.error("Cookie is missing.");
                throw new Exception("Authorization cookie is missing.");
            }

            Identity identity = identityRepository.findByUsername(username)
                    .orElseThrow(() -> {
                        LOGGER.error("Identity not found for username: " + username);
                        return new Exception("Identity not found.");
                    });

            // Check if the account is activated
            if (!identity.isAccountActivated()) {
                var location = UriBuilder.fromUri(cookie.getValue().split("\\$")[1])
                        .queryParam("error", "Account not activated.")
                        .queryParam("error_description", "Please verify your account before logging in.")
                        .build();
                return Response.status(Response.Status.FORBIDDEN)
                        .entity("Account not activated. Please verify your account before logging in.")
                        .location(location)
                        .build();
            }

            if (argon2Utils.check(identity.getPassword(), password.toCharArray())) {
                MultivaluedMap<String, String> params = uriInfo.getQueryParameters();
                String redirectURI = buildActualRedirectURI(
                        cookie.getValue().split("\\$")[1],
                        params.getFirst("response_type"),
                        cookie.getValue().split("#")[0],
                        username,
                        "resource.read,resource.write",
                        params.getFirst("code_challenge"), params.getFirst("state")
                );
                return Response.seeOther(UriBuilder.fromUri(redirectURI).build()).build();
            } else {

                var location = UriBuilder.fromUri(cookie.getValue().split("\\$")[1])
                        .queryParam("error", "User doesn't approved the request.")
                        .queryParam("error_description", "User doesn't approved the request.")
                        .build();
                return Response.seeOther(location).build();
            }
        } catch (Exception e) {
            LOGGER.error("Error during login: ", e);
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                    .entity("An error occurred during login. Please try again later.")
                    .build();
        }
    }

    private String buildActualRedirectURI(String redirectUri,String responseType,String clientId,String userId,String approvedScopes,String codeChallenge,String state) throws Exception {
        StringBuilder sb = new StringBuilder(redirectUri);
        if ("code".equals(responseType)) {
            AuthorizationCode authorizationCode = new AuthorizationCode(clientId,userId,
                    approvedScopes, Instant.now().plus(2, ChronoUnit.MINUTES).getEpochSecond(),redirectUri);
            sb.append("?code=").append(URLEncoder.encode(authorizationCode.getCode(codeChallenge), StandardCharsets.UTF_8));
        } else {
            //Implicit: responseType=token : Not Supported
            return null;
        }
        if (state != null) {
            sb.append("&state=").append(state);
        }
        return sb.toString();
    }
    private Response informUserAboutError(String error) {
        String errorMessage = String.format(
                "<!DOCTYPE html>" +
                        "<html>" +
                        "<head>" +
                        "<meta charset=\"UTF-8\"/>" +
                        "<title>Error</title>" +
                        "</head>" +
                        "<body>" +
                        "<aside class=\"container\">" +
                        "<h1>Error Occurred</h1>" +
                        "<p>%s</p>" +
                        "</aside>" +
                        "</body>" +
                        "</html>", error);

        // Return the HTML response with status 400 (Bad Request)
        return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorMessage)
                .type(MediaType.TEXT_HTML)
                .build();
    }
}
