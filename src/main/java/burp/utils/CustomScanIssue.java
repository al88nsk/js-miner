package burp.utils;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;

//
// Helper class to build a custom (Montoya) audit issue to hold our custom scan issue details
//

public class CustomScanIssue {

    private CustomScanIssue() {
    }

    /**
     * Build an {@link AuditIssue} bound to the provided request/response.
     *
     * @param httpRequestResponse The HTTP request/response that triggered the issue
     * @param name                The name of the issue type
     * @param detail              Detailed information about the issue
     * @param background          The background description of the issue type
     * @param severity            The {@link AuditIssueSeverity} level
     * @param confidence          The {@link AuditIssueConfidence} level
     */
    public static AuditIssue create(
            HttpRequestResponse httpRequestResponse,
            String name,
            String detail,
            String background,
            AuditIssueSeverity severity,
            AuditIssueConfidence confidence) {
        return create(name, detail, background, severity, confidence,
                httpRequestResponse.request().url(),
                httpRequestResponse);
    }

    /**
     * Build an {@link AuditIssue} with an explicit base URL (useful when the issue is not
     * tied to a specific request, e.g. the "Static Files Dumper" issue).
     *
     * @param name           The name of the issue type
     * @param detail         Detailed information about the issue
     * @param background     The background description of the issue type
     * @param severity       The {@link AuditIssueSeverity} level
     * @param confidence     The {@link AuditIssueConfidence} level
     * @param baseUrl        The base URL for which the issue is generated
     * @param requestResponses Optional HTTP request/response messages associated with the issue
     */
    public static AuditIssue create(
            String name,
            String detail,
            String background,
            AuditIssueSeverity severity,
            AuditIssueConfidence confidence,
            String baseUrl,
            HttpRequestResponse... requestResponses) {
        return AuditIssue.auditIssue(
                name,
                detail,
                null,
                baseUrl,
                severity,
                confidence,
                background,
                null,
                severity,
                requestResponses);
    }
}
