package burp.utils;

import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.google.re2j.Pattern;

import static burp.BurpExtender.mStdErr;

/**
 * A single known secret-token detection pattern (name + regex + severity/confidence).
 * The regex is compiled once at load time using RE2J (linear time, no catastrophic
 * backtracking). A pattern that fails to compile is skipped rather than aborting
 * the extension (its {@link #pattern} is {@code null}).
 *
 * <p>This pattern-based detection model follows the approach used by
 * <a href="https://github.com/trinetlayer/Ghost-Js-Burp-Extension">Ghost-JS-Burp-Extension</a>
 * (MIT licensed): instead of relying only on generic assignment-style secrets, each
 * well-known token format gets its own tight regex.
 */
public final class SecretPattern {
    public final String name;
    public final Pattern pattern;
    public final AuditIssueSeverity severity;
    public final AuditIssueConfidence confidence;

    public SecretPattern(String name, String regex, int patternFlags, AuditIssueSeverity severity, AuditIssueConfidence confidence) {
        this.name = name;
        this.pattern = compileSafely(name, regex, patternFlags);
        this.severity = severity;
        this.confidence = confidence;
    }

    private static Pattern compileSafely(String name, String regex, int flags) {
        try {
            return Pattern.compile(regex, flags);
        } catch (RuntimeException e) {
            mStdErr.println("[-] Failed to compile secret pattern '" + name + "': " + e.getMessage());
            return null;
        }
    }
}
