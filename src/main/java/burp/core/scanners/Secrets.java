package burp.core.scanners;

import burp.BurpExtender;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.utils.SecretPattern;
import burp.utils.SecretPatterns;
import burp.utils.Utilities;
import com.google.re2j.Matcher;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import static burp.utils.Constants.*;
import static burp.utils.Utilities.*;

public class Secrets implements Runnable {
    private final HttpRequestResponse baseRequestResponse;
    private final UUID taskUUID;

    public Secrets(HttpRequestResponse baseRequestResponse, UUID taskUUID) {
        this.baseRequestResponse = baseRequestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);
        String responseBodyString = baseRequestResponse.response().body().toString();

        // Combined secrets
        Matcher matcherSecrets = SECRETS_REGEX.matcher(responseBodyString);
        // For reporting unique matches with markers
        List<byte[]> uniqueMatchesLow = new ArrayList<>();
        StringBuilder uniqueMatchesSBLow = new StringBuilder();

        List<byte[]> uniqueMatchesHigh = new ArrayList<>();
        StringBuilder uniqueMatchesSBHigh = new StringBuilder();
        while (matcherSecrets.find() && BurpExtender.isLoaded()) {
            if (Utilities.isHighEntropy(matcherSecrets.group(20))) { // group(20) matches our secret
                // if high entropy, confidence is "Firm"
                uniqueMatchesHigh.add(matcherSecrets.group().getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(matcherSecrets.group(), uniqueMatchesSBHigh);
            } else {
                // if low entropy, confidence is "Tentative"
                if (isNotFalsePositive(matcherSecrets.group(20))) {
                    uniqueMatchesLow.add(matcherSecrets.group().getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(matcherSecrets.group(), uniqueMatchesSBLow);
                }
            }
        }

        // http basic auth secrets
        Matcher httpBasicAuthMatcher = HTTP_BASIC_AUTH_SECRETS.matcher(responseBodyString);
        if (httpBasicAuthMatcher.find()) {
            String base64String = httpBasicAuthMatcher.group(2); // basic auth secret is in group(2)

            // checks if secret is a valid base64 & of high entropy
            if (isValidBase64(base64String) && Utilities.isHighEntropy(Utilities.b64Decode(base64String))) {
                uniqueMatchesHigh.add(httpBasicAuthMatcher.group().getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(httpBasicAuthMatcher.group(), uniqueMatchesSBHigh);
            } else {
                // otherwise, report it anyway (as Low)
                uniqueMatchesLow.add(httpBasicAuthMatcher.group().getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(httpBasicAuthMatcher.group(), uniqueMatchesSBLow);
            }
        }

        reportFinding(baseRequestResponse, uniqueMatchesSBLow, uniqueMatchesLow, uniqueMatchesSBHigh, uniqueMatchesHigh);

        // Pattern-based detection of known secret tokens (GitHub tokens, JWTs, cloud/SaaS keys, ...)
        scanKnownSecretTokens(baseRequestResponse, responseBodyString);

        BurpExtender.getTaskRepository().completeTask(taskUUID);
    }

    /*
     *  Detect well-known hardcoded secret token formats (e.g. GitHub tokens, JWTs, API keys)
     *  using the pattern list from SecretPatterns. Each pattern reports its own issue, so the
     *  severity/confidence of the token format is preserved.
     */
    private static void scanKnownSecretTokens(HttpRequestResponse baseRequestResponse, String responseBodyString) {
        for (SecretPattern secretPattern : SecretPatterns.ALL) {
            if (!BurpExtender.isLoaded() || secretPattern.pattern == null) {
                continue;
            }
            // For reporting unique matches with markers
            List<byte[]> uniqueMatches = new ArrayList<>();
            StringBuilder uniqueMatchesSB = new StringBuilder();

            Matcher patternMatcher = secretPattern.pattern.matcher(responseBodyString);
            while (patternMatcher.find() && BurpExtender.isLoaded()) {
                String matchedToken = patternMatcher.group();
                // Skip documentation examples / placeholders (e.g. "ghp_xxxx...", "your_token_here")
                if (isLikelyPlaceholder(matchedToken)) {
                    continue;
                }
                uniqueMatches.add(matchedToken.getBytes(StandardCharsets.UTF_8));
                appendFoundMatches(matchedToken, uniqueMatchesSB);
            }

            if (uniqueMatchesSB.length() > 0) {
                List<Marker> tokenMatches = getMatches(baseRequestResponse.response().toByteArray(), uniqueMatches);
                sendNewIssue(baseRequestResponse,
                        "[JS Miner] " + secretPattern.name,
                        "The following hardcoded secret tokens were found in a static file.",
                        uniqueMatchesSB.toString(),
                        tokenMatches,
                        secretPattern.severity,
                        secretPattern.confidence
                );
            }
        }
    }

    /*
     *  Heuristic to skip documentation samples / placeholder values that happen to match a
     *  known token format (e.g. "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx").
     */
    private static boolean isLikelyPlaceholder(String matchedSecret) {
        String lowerCaseSecret = matchedSecret.toLowerCase(Locale.ENGLISH);
        return lowerCaseSecret.contains("example")
                || lowerCaseSecret.contains("sample")
                || lowerCaseSecret.contains("your_")
                || lowerCaseSecret.contains("your-")
                || lowerCaseSecret.contains("xxxxx")
                || lowerCaseSecret.contains("placeholder")
                || lowerCaseSecret.contains("changeme");
    }

    private static void reportFinding(HttpRequestResponse baseRequestResponse, StringBuilder uniqueMatchesSBLow, List<byte[]> uniqueMatchesLow,
                                      StringBuilder uniqueMatchesSBHigh, List<byte[]> uniqueMatchesHigh) {
        if (uniqueMatchesSBHigh.length() > 0) {
            List<Marker> secretsMatchesHigh = getMatches(baseRequestResponse.response().toByteArray(), uniqueMatchesHigh);
            sendNewIssue(baseRequestResponse,
                    "[JS Miner] Secrets / Credentials",
                    "The following secrets (with High entropy) were found in a static file.",
                    uniqueMatchesSBHigh.toString(),
                    secretsMatchesHigh,
                    SEVERITY_MEDIUM,
                    CONFIDENCE_FIRM
            );
        }

        if (uniqueMatchesSBLow.length() > 0) {
            List<Marker> secretsMatchesLow = getMatches(baseRequestResponse.response().toByteArray(), uniqueMatchesLow);
            sendNewIssue(baseRequestResponse,
                    "[JS Miner] Secrets / Credentials",
                    "The following secrets (with Low entropy) were found in a static file.",
                    uniqueMatchesSBLow.toString(),
                    secretsMatchesLow,
                    SEVERITY_MEDIUM,
                    CONFIDENCE_TENTATIVE
            );
        }
    }

    private static boolean isNotFalsePositive(String secret) {
        String[] falsePositives = {"basic", "bearer", "token"};
        // cleanup the secret string
        secret = secret.replaceAll("\\s", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("\n", "")
                .replace("*", "");
        // at least the secret should equal 4 characters
        if (secret.length() <= 4) {
            return false;
        }

        // Check if secret string is not in the pre-defined blacklist
        for (String fp: falsePositives) {
            if (secret.equalsIgnoreCase(fp)) {
                return false;
            }
        }

        return true;
    }
}
