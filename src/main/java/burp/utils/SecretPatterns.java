package burp.utils;

import java.util.List;

import static burp.utils.Constants.*;

/**
 * The list of known hardcoded secret patterns scanned for by the Secrets scanner
 * (e.g. GitHub tokens, JWTs, cloud/SaaS API keys). Each entry is a tight regex for
 * a well-known token format, with a matching severity/confidence. Add new token
 * formats here to extend detection.
 */
public final class SecretPatterns {

    private SecretPatterns() {
    }

    public static final List<SecretPattern> ALL = List.of(
            // GitHub tokens (https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/about-authentication-to-github)
            new SecretPattern("GitHub Personal Access Token", "\\bghp_[0-9A-Za-z]{36}\\b", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("GitHub OAuth / App Token", "\\bg(ho|hu|hs|hr)_[0-9A-Za-z]{36}\\b", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("GitHub Fine-grained Personal Access Token", "github_pat_[0-9A-Za-z_]{22}_[0-9A-Za-z_]{59}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),

            // JWT (three base64url segments without padding per RFC 7519; header always starts with "eyJ").
            // Length floors per segment keep random base64 strings from matching.
            new SecretPattern("JWT", "eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}", 0, SEVERITY_MEDIUM, CONFIDENCE_FIRM),

            // Cloud providers
            // AWS access key IDs are 20 characters total: "AKIA" + 16 (e.g. AKIAIOSFODNN7EXAMPLE)
            new SecretPattern("AWS Access Key ID", "AKIA[0-9A-Z]{16}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("Google API Key", "AIza[0-9A-Za-z\\-_]{35}", 0, SEVERITY_MEDIUM, CONFIDENCE_CERTAIN),

            // SaaS / messaging tokens
            new SecretPattern("Slack Token", "xox[baprs]-[0-9A-Za-z-]{10,}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("Slack Webhook URL", "https://hooks\\.slack\\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+(/[A-Za-z0-9]+)?", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("Stripe Live Secret Key", "sk_live_[0-9A-Za-z]{24,}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("Stripe Live Restricted Key", "rk_live_[0-9A-Za-z]{24,}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("Twilio API Key", "SK[0-9a-fA-F]{32}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("SendGrid API Key", "SG\\.[0-9A-Za-z\\-_]{22}\\.[0-9A-Za-z\\-_]{43}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            // Modern OpenAI keys: legacy "sk-", project-scoped "sk-proj-", org "sk-org-", service accounts "sk-svcacct-"
            new SecretPattern("OpenAI API Key", "sk-(proj-|org-|svcacct-)?-?[A-Za-z0-9]{32,}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            // Modern GitLab PATs are 26 chars; legacy ones were 20
            new SecretPattern("GitLab Personal Access Token", "glpat-[0-9A-Za-z\\-_]{20,26}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("Shopify Access Token", "shpat_[0-9a-fA-F]{32}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("npm Access Token", "npm_[0-9A-Za-z]{36}", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN),
            new SecretPattern("Discord Webhook URL", "https://(canary\\.)?discord\\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+", 0, SEVERITY_MEDIUM, CONFIDENCE_CERTAIN),

            // Private keys (PEM headers)
            new SecretPattern("Private Key", "-----BEGIN (RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----", 0, SEVERITY_HIGH, CONFIDENCE_CERTAIN)
    );
}
