package tn.cyber.boundaries;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import tn.cyber.repositories.TenantRepository;
import tn.cyber.services.IdentityServices;

import java.io.InputStream;
import java.util.Objects;
import java.util.logging.Level;
import java.util.logging.Logger;

@Path("/")
public class IdentityRegistrationEndpoint {

    private static final Logger LOGGER = Logger.getLogger(IdentityRegistrationEndpoint.class.getName());

    @Inject
    IdentityServices identityServices;

    @Inject
    TenantRepository tenantRepository;

    @GET
    @Path("/register/authorize")
    @Produces(MediaType.TEXT_HTML)
    public Response authorizeRegistration(@Context UriInfo uriInfo) {
        try {
            MultivaluedMap<String, String> params = uriInfo.getQueryParameters();

            // Validate client_id
            String clientId = params.getFirst("client_id");
            if (isNullOrEmpty(clientId)) {
                return informUserAboutError("Invalid client_id: " + clientId);
            }

            var tenant = tenantRepository.findByName(clientId);
            if (tenant == null) {
                return informUserAboutError("Invalid client_id: " + clientId);
            }

            // Validate redirectUri
            String redirectUri = params.getFirst("redirect_uri");
            if (!isRedirectUriValid(tenant.getRedirectUri(), redirectUri)) {
                return informUserAboutError("Invalid or mismatched redirect_uri");
            }

            // Stream the registration page
            StreamingOutput stream = createHtmlResponse("/Register.html");
            return Response.ok(stream)
                    .location(uriInfo.getBaseUri().resolve("/register"))
                    .build();

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during authorization: ", e);
            return informUserAboutError("An unexpected error occurred.");
        }
    }
    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    @Produces(MediaType.TEXT_HTML)
    public Response register(@FormParam("username") String username,
                             @FormParam("email") String email,
                             @FormParam("password") String password) {
        try {
            identityServices.registerIdentity(username, password, email);

            // Stream the confirmation page
            StreamingOutput stream = createHtmlResponse("/Activate.html");
            return Response.ok(stream).build();

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during registration: ", e);
            return informUserAboutError(e.getMessage());
        }
    }

    @POST
    @Path("/register/activate")
    public Response activate(@FormParam("code") String code) {
        try {
            identityServices.activateIdentity(code);
            return Response.ok().build();

        } catch (Exception e) {
            LOGGER.log(Level.SEVERE, "Error during activation: ", e);
            return informUserAboutError(e.getMessage());
        }
    }

    /**
     * Helper method to validate redirectUri.
     */
    private boolean isRedirectUriValid(String tenantRedirectUri, String providedRedirectUri) {
        if (!isNullOrEmpty(tenantRedirectUri)) {
            return providedRedirectUri != null && providedRedirectUri.equals(tenantRedirectUri);
        }
        return !isNullOrEmpty(providedRedirectUri);
    }

    /**
     * Helper method to create an HTML response from a file.
     */
    private StreamingOutput createHtmlResponse(String filePath) {
        return output -> {
            try (InputStream is = Objects.requireNonNull(getClass().getResource(filePath)).openStream()) {
                output.write(is.readAllBytes());
            } catch (Exception e) {
                LOGGER.log(Level.SEVERE, "Error streaming HTML file: " + filePath, e);
                throw new WebApplicationException("Failed to load HTML content.", e);
            }
        };
    }

    /**
     * Helper method to check if a string is null or empty.
     */
    private boolean isNullOrEmpty(String str) {
        return str == null || str.isEmpty();
    }

    /**
     * Helper method to inform the user about an error using HTML.
     */
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

        return Response.status(Response.Status.BAD_REQUEST)
                .entity(errorMessage)
                .type(MediaType.TEXT_HTML)
                .build();
    }
}
