package burp.core.scanners;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.utils.Utilities;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static burp.BurpExtender.mStdErr;
import static burp.utils.Constants.*;
import static burp.utils.Utilities.appendFoundMatches;
import static burp.utils.Utilities.sendNewIssue;

public class SubDomains implements Runnable {
    private static final MontoyaApi api = BurpExtender.getApi();
    private final HttpRequestResponse baseRequestResponse;
    private final UUID taskUUID;

    public SubDomains(HttpRequestResponse baseRequestResponse, UUID taskUUID) {
        this.baseRequestResponse = baseRequestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);

        String responseBodyString = baseRequestResponse.response().body().toString();
        String domainFromReferer = Utilities.getDomainFromReferer(baseRequestResponse);
        String requestDomain = getRequestHost(baseRequestResponse);
        String rootDomain;
        // Try to get caller domain from Referer header (to avoid matching cdn subdomains, ..etc.)
        if (domainFromReferer != null) {
            rootDomain = domainFromReferer;
        } else {
            // If the above failed, then use the domain from the HTTP request
            rootDomain = Utilities.getRootDomain(requestDomain);
        }

        if (rootDomain != null) {
            // For reporting unique matches with markers
            List<byte[]> uniqueMatches = new ArrayList<>();
            StringBuilder uniqueMatchesSB = new StringBuilder();

            // Simple SubDomains Regex
            Pattern subDomainsRegex = Pattern.compile("([a-z-0-9]+[.])+" + rootDomain, Pattern.CASE_INSENSITIVE);
            Matcher matcherSubDomains = subDomainsRegex.matcher(responseBodyString);
            while (matcherSubDomains.find() && BurpExtender.isLoaded()) {
                if (
                        Utilities.isMatchedDomainValid(matcherSubDomains.group(), rootDomain, requestDomain)
                ) {
                    String decodedMatch = api.utilities().urlUtils().decode(matcherSubDomains.group());
                    uniqueMatches.add(decodedMatch.getBytes(StandardCharsets.UTF_8));
                    appendFoundMatches(decodedMatch, uniqueMatchesSB);
                }
            }
            reportFinding(baseRequestResponse, uniqueMatchesSB, uniqueMatches);
        }
        BurpExtender.getTaskRepository().completeTask(taskUUID);
    }

    private static String getRequestHost(HttpRequestResponse baseRequestResponse) {
        try {
            return new URL(baseRequestResponse.request().url()).getHost();
        } catch (MalformedURLException e) {
            mStdErr.println("[-] MalformedURLException");
            return null;
        }
    }

    private static void reportFinding(HttpRequestResponse baseRequestResponse, StringBuilder allMatchesSB, List<byte[]> uniqueMatches) {
        if (allMatchesSB.length() > 0) {
            // Get markers of found Cloud URL Matches
            List<Marker> allMatchesMarkers = Utilities.getMatches(baseRequestResponse.response().toByteArray(), uniqueMatches);

            // report the issue
            sendNewIssue(baseRequestResponse,
                    "[JS Miner] Subdomains",
                    "The following subdomains were found in a static file.",
                    allMatchesSB.toString(),
                    allMatchesMarkers,
                    SEVERITY_INFORMATION,
                    CONFIDENCE_CERTAIN
            );
        }
    }
}
