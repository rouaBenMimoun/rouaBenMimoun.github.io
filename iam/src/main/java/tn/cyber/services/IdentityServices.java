package tn.cyber.services;

import jakarta.ejb.EJBException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.apache.commons.lang3.tuple.Pair;
import tn.cyber.entities.Identity;
import tn.cyber.enums.Role;
import tn.cyber.repositories.IdentityRepository;
import tn.cyber.security.Argon2Utils;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

@ApplicationScoped
public class IdentityServices {

    private static final Logger LOGGER = Logger.getLogger(IdentityServices.class.getName());

    @Inject
    private IdentityRepository identityRepository;

    @Inject
    private Argon2Utils argon2Utils;

    @Inject
    private EmailService emailService;

    private static final String ACTIVATION_EMAIL_SENDER = "rouamadridistacr7@gmail.com";
    private static final String ACTIVATION_EMAIL_SUBJECT = "Activate Account";
    private static final String ACTIVATION_EMAIL_TEMPLATE =
            "Dear User,\n\n" +
                    "Thank you for choosing our CyberSecurity application for steganography! We are excited to have you onboard.\n\n" +
                    "To complete your account setup, please use the activation code below:\n\n" +
                    "Activation Code: %s\n\n" +
                    "⚠️ Please note: This code is valid for the next 5 minutes.\n\n" +
                    "If you did not request this activation or need assistance, please contact our support team immediately.\n\n" +
                    "Best regards,\n" +
                    "The Cybersecurity Steganography App Team";

    private static final int ACTIVATION_CODE_LENGTH = 6;
    private static final int ACTIVATION_CODE_EXPIRATION_MINUTES = 5;
    private static final int MIN_PASSWORD_LENGTH = 8;

    private final Map<String, Pair<String, LocalDateTime>> activationCodes = new HashMap<>();

    public void registerIdentity(String username, String password, String email) {
        // Validate inputs
        validateIdentity(username, email);
        validatePassword(password);

        LOGGER.info("Registering identity: " + username);

        // Create and save the new identity
        Identity identity = createNewIdentity(username, password, email);
        identityRepository.save(identity);

        // Generate and send activation code
        String activationCode = generateActivationCode();
        LocalDateTime expirationTime = LocalDateTime.now().plusMinutes(ACTIVATION_CODE_EXPIRATION_MINUTES);
        activationCodes.put(activationCode, Pair.of(identity.getEmail(), expirationTime));

        String emailMessage = String.format(ACTIVATION_EMAIL_TEMPLATE, activationCode);
        emailService.sendEmail(ACTIVATION_EMAIL_SENDER, identity.getEmail(), ACTIVATION_EMAIL_SUBJECT, emailMessage);

        LOGGER.info("Activation code sent to: " + email);
    }

    private void validatePassword(String password) {
        if (password == null || password.isEmpty()) {
            throw new EJBException("Password is required.");
        }
        if (password.length() < MIN_PASSWORD_LENGTH) {
            throw new EJBException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long.");
        }
        if (!password.matches(".*\\d.*")) { // At least one digit
            throw new EJBException("Password must contain at least one number.");
        }
        if (!password.matches(".*[!@#$%^&*(),.?\":{}|<>].*")) { // At least one special character
            throw new EJBException("Password must contain at least one special character.");
        }
    }

    public void activateIdentity(String code) {
        // Fetch activation code details
        Pair<String, LocalDateTime> codeDetails = activationCodes.get(code);
        if (codeDetails == null) {
            throw new EJBException("Invalid activation code.");
        }

        String email = codeDetails.getLeft();
        LocalDateTime expirationTime = codeDetails.getRight();

        if (LocalDateTime.now().isAfter(expirationTime)) {
            activationCodes.remove(code);
            deleteIdentityByEmail(email);
            throw new EJBException("Activation code expired.");
        }

        Identity identity = identityRepository.findByEmail(email).orElseThrow(() ->
                new EJBException("Identity associated with the activation code not found."));
        identity.setAccountActivated(true);
        identityRepository.save(identity);

        activationCodes.remove(code);
        LOGGER.info("Activated identity: " + email);
    }

    private void validateIdentity(String username, String email) {
        if (username == null || username.isEmpty()) {
            throw new EJBException("Username is required.");
        }
        if (email == null || email.isEmpty()) {
            throw new EJBException("Email is required.");
        }
        if (identityRepository.findByUsername(username).isPresent()) {
            throw new EJBException("An identity with username '" + username + "' already exists.");
        }
        if (identityRepository.findByEmail(email).isPresent()) {
            throw new EJBException("An identity with email '" + email + "' already exists.");
        }
    }

    private Identity createNewIdentity(String username, String password, String email) {
        Identity identity = new Identity();
        identity.setUsername(username);
        identity.setPassword(password);
        identity.setEmail(email);
        identity.setCreationDate(LocalDateTime.now().toString());
        identity.setRoles(Role.R_P00.getValue());
        identity.setScopes("resource:read resource:write");
        identity.hashPassword(password, argon2Utils);

        LOGGER.info("Created new identity: " + username);
        return identity;
    }

    private void deleteIdentityByEmail(String email) {
        identityRepository.findByEmail(email).ifPresent(identityRepository::delete);
        LOGGER.info("Deleted identity with email: " + email);
    }

    private String generateActivationCode() {
        SecureRandom secureRandom = new SecureRandom();
        StringBuilder codeBuilder = new StringBuilder(ACTIVATION_CODE_LENGTH);
        String characters = "0123456789";

        for (int i = 0; i < ACTIVATION_CODE_LENGTH; i++) {
            int randomIndex = secureRandom.nextInt(characters.length());
            codeBuilder.append(characters.charAt(randomIndex));
        }

        return codeBuilder.toString();
    }
}
