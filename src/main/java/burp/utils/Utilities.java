package burp.utils;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.sitemap.SiteMapFilter;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import com.google.re2j.Matcher;
import com.google.re2j.Pattern;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.function.Predicate;

import static burp.BurpExtender.*;
import static burp.utils.Constants.*;

public final class Utilities {
    private static final Pattern FILE_NAME_REGEX = Pattern.compile("(.*)\\.(.*)");

    private Utilities() {
    }

    private static final MontoyaApi api = BurpExtender.getApi();

    /*
     *  Issue collection for the passive scan check.
     *  When a thread-local collector is active (set by the passive scan check), findings are
     *  collected and returned to Burp through the scan check's AuditResult - the Dashboard
     *  integrated reporting path. Otherwise (manually invoked context-menu scans), findings
     *  are reported out-of-band through SiteMap.add(AuditIssue), which is the API's designated
     *  mechanism for tasks outside the normal testing workflow.
     */
    private static final ThreadLocal<List<AuditIssue>> PASSIVE_ISSUE_COLLECTOR = new ThreadLocal<>();

    public static void beginIssueCollection() {
        PASSIVE_ISSUE_COLLECTOR.set(new ArrayList<>());
    }

    public static List<AuditIssue> finishIssueCollection() {
        List<AuditIssue> issues = PASSIVE_ISSUE_COLLECTOR.get();
        PASSIVE_ISSUE_COLLECTOR.remove();
        return issues != null ? issues : Collections.emptyList();
    }

    /**
     * Safe {@link URL} builder for URLs reported by Burp (which are always valid absolute URLs).
     * Returns {@code null} on malformed input.
     */
    public static URL toURL(String url) {
        try {
            return new URL(url);
        } catch (MalformedURLException e) {
            mStdErr.println("[-] MalformedURLException: " + url);
            return null;
        }
    }

    /*
     *  This is mainly used by the "querySiteMap" function
     *  Checks if the HTTP Response is not null and that the Requested file is either JS or JSON
     */
    public static boolean isValidScanTarget(HttpRequestResponse baseRequestResponse, String[] queryFileExtensions) {
        if (baseRequestResponse.hasResponse() && BurpExtender.isLoaded()) {
            for (String fileExtension: queryFileExtensions) {
                // pathWithoutQuery() to ignore query strings (e.g. "/app.js?v=1" still matches ".js")
                if (baseRequestResponse.request().pathWithoutQuery().endsWith("." + fileExtension)) {
                    return true;
                }
            }
        }
        return false;
    }

    /*
     *  Query Site Map for specific extensions (including children of the passed Request URL)
     */
    public static List<HttpRequestResponse> querySiteMap(List<HttpRequestResponse> httpReqResArray, String[] queryFileExtensions) {
        return querySiteMap(httpReqResArray, requestResponse -> isValidScanTarget(requestResponse, queryFileExtensions));
    }

    /*
     *  Query Site Map for messages matching the given filter (including children of the passed Request URL)
     */
    public static List<HttpRequestResponse> querySiteMap(List<HttpRequestResponse> httpReqResArray, Predicate<HttpRequestResponse> targetFilter) {
        Set<HttpRequestResponse> uniqueRequests = new LinkedHashSet<>();
        for (HttpRequestResponse baseRequestResponse : httpReqResArray) {
            URL baseURL = toURL(baseRequestResponse.request().url());
            if (baseURL == null) {
                continue;
            }
            String urlPrefix = getURLPrefix(baseURL);
            // Get all child URLs from Site Map
            List<HttpRequestResponse> siteMapReqResArray = api.siteMap().requestResponses(SiteMapFilter.prefixFilter(urlPrefix));
            for (HttpRequestResponse requestResponse : siteMapReqResArray) {
                if (targetFilter.test(requestResponse)) {
                    uniqueRequests.add(requestResponse);
                }
            }
        }
        return new ArrayList<>(uniqueRequests);
    }

    /*
     *  Returns the response's "Content-Type" header value, lowercased, or an empty string if absent.
     */
    public static String getResponseContentType(HttpRequestResponse requestResponse) {
        if (requestResponse.hasResponse()) {
            String contentType = requestResponse.response().headerValue("Content-Type");
            return contentType != null ? contentType.toLowerCase(Locale.ENGLISH) : "";
        }
        return "";
    }

    /*
     *  True if the response looks like HTML. Detection is based on the response's "Content-Type"
     *  header (so extensionless URLs such as "/" or "/home" are covered), falling back to the
     *  ".html"/".htm" file extension only when no "Content-Type" header is present.
     */
    public static boolean isHTMLResponse(HttpRequestResponse requestResponse) {
        if (!requestResponse.hasResponse()) {
            return false;
        }
        String contentType = getResponseContentType(requestResponse);
        if (!contentType.isEmpty()) {
            return contentType.contains("text/html") || contentType.contains("application/xhtml+xml");
        }
        String path = requestResponse.request().pathWithoutQuery();
        return path.endsWith(".html") || path.endsWith(".htm");
    }

    // Append found matches to be listed in Burp's issues
    public static void appendFoundMatches(String finding, StringBuilder uniqueMatchesSB) {
        // Only report unique instances
        if (uniqueMatchesSB.indexOf(HTML_LIST_BULLET_OPEN + finding + HTML_LIST_BULLET_CLOSED) == -1) {
            uniqueMatchesSB.append(HTML_LIST_BULLET_OPEN);
            uniqueMatchesSB.append(finding);
            uniqueMatchesSB.append(HTML_LIST_BULLET_CLOSED);
        }
    }

    /**
     * An improved version of the getMatches method to search an HTTP response for occurrences of a unique matches
     * and return a sorted list of start/end offsets
     */
    public static List<Marker> getMatches(ByteArray response, List<byte[]> uniqueMatches)
    {
        List<Marker> matches = new ArrayList<>();

        for (byte[] match: uniqueMatches) {
            ByteArray matchByteArray = ByteArray.byteArray(match);
            // Limit Response highlighters (matches) only to 500 then break (to maintain performance)
            if (matches.size() < 500) {
                int start = 0;
                while (start < response.length())
                {
                    start = response.indexOf(matchByteArray, false, start, response.length());
                    if (start == -1)
                        break;
                    matches.add(Marker.marker(start, start + matchByteArray.length()));
                    start += matchByteArray.length();
                }
            } else {
                break;
            }
        }
        // Sort found matches or otherwise Burp will complain (Source: https://stackoverflow.com/questions/19596950/sort-an-arraylist-of-integer-arrays)
        matches.sort(new Comparator<Marker>() {
            @Override
            public int compare(Marker o1, Marker o2) {
                return Integer.compare(o1.range().startIndexInclusive(), o2.range().startIndexInclusive());
            }
        });

        // Dirty trick to fix overlapping offsets
        for (int i = 0; i < matches.size(); i++) {
            if (i + 1 != matches.size()
                    && matches.get(i).range().endIndexExclusive() > matches.get(i + 1).range().startIndexInclusive()) {
                Marker fixed = Marker.marker(matches.get(i).range().startIndexInclusive(), matches.get(i + 1).range().startIndexInclusive());
                matches.set(i, fixed);
            }
        }

        return matches;
    }


    public static byte[] getHTTPResponseBodyHash(HttpRequestResponse baseRequestResponse) {
        if (baseRequestResponse.hasResponse()) {
            // Get bytes of Response content
            ByteArray responseBody = baseRequestResponse.response().body();
            byte[] responseBodyBytes = responseBody.getBytes();
            MessageDigest digest = null;
            try {
                digest = MessageDigest.getInstance("SHA-256");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            return digest != null ? digest.digest(responseBodyBytes) : new byte[0];
        } else {
            return new byte[0];
        }
    }


    // template issue for interesting stuff
    public static void sendNewIssue(
            HttpRequestResponse baseRequestResponse,
            String issueName,
            String description,
            String issueHighlight,
            List<Marker> responseMarkers,
            AuditIssueSeverity severity,
            AuditIssueConfidence confidence
    ) {
        // Apply markers to the response so the matches are highlighted in the HTTP response
        HttpRequestResponse markedRequestResponse = baseRequestResponse.withResponseMarkers(responseMarkers);

        AuditIssue newCustomIssue = CustomScanIssue.create(
                markedRequestResponse,
                issueName,
                SCAN_ISSUE_HEADER +
                        description +
                        HTML_LIST_OPEN +
                        issueHighlight+
                        HTML_LIST_CLOSED +
                        "The identified matches should be highlighted in the HTTP response.<br><br>" +
                        "<br>",
                null,
                severity,
                confidence
        );

        Utilities.reportIssueIfNotDuplicate(newCustomIssue);
    }

    public static void reportIssueIfNotDuplicate(AuditIssue auditIssue) {
        synchronized (Utilities.class) {
            List<AuditIssue> pendingIssues = PASSIVE_ISSUE_COLLECTOR.get();
            if (pendingIssues != null) {
                // Passive scans (invoked synchronously from the passive scan check): collect the
                // issue so it can be returned to Burp via the check's AuditResult.
                if (isNewIssue(auditIssue, pendingIssues)) {
                    pendingIssues.add(auditIssue);
                }
            } else if (isNewIssue(auditIssue, null)) {
                // Manually-invoked scans: report out-of-band to Burp's site map.
                api.siteMap().add(auditIssue);
            }
        }
    }

    private static boolean isNewIssue(AuditIssue auditIssueCheck, List<AuditIssue> extraIssues) {
        List<AuditIssue> allIssues = api.siteMap().issues();
        for (AuditIssue auditIssue : allIssues) {
            if (isSameIssue(auditIssue, auditIssueCheck)) {
                return false;
            }
        }
        if (extraIssues != null) {
            for (AuditIssue auditIssue : extraIssues) {
                if (isSameIssue(auditIssue, auditIssueCheck)) {
                    return false;
                }
            }
        }
        return true;
    }

    private static boolean isSameIssue(AuditIssue issueA, AuditIssue issueB) {
        return Objects.equals(issueA.name(), issueB.name())
                && Objects.equals(issueA.detail(), issueB.detail());
    }

    public static URL trimURL(URL url) {
        String host = url.getHost();
        String string = url.toString().replaceAll(host + ".*", host);
        try {
            return new URL(string);
        } catch (MalformedURLException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static String getRootDomain(String requestDomain) {
        // Get root Domain (e.g.: example.com instead of sub.example.com)
        Pattern rootDomainRegex = Pattern.compile("[a-z0-9]+.[a-z0-9]+$", Pattern.CASE_INSENSITIVE);
        Matcher matcherRootDomain = rootDomainRegex.matcher(requestDomain);
        if (matcherRootDomain.find() && BurpExtender.isLoaded()) {
            return matcherRootDomain.group();
        }
        return null;
    }

    /**
     * Get domain from "Referer" header to search the caller domain instead of a cdn for example
     */
    public static String getDomainFromReferer(HttpRequestResponse baseRequestResponse) {
        String referer = baseRequestResponse.request().headerValue("Referer");
        if (referer != null) {
            try {
                URI domainURI = new URI(referer);
                return getRootDomain(domainURI.getHost());
            } catch (URISyntaxException e) {
                mStdErr.println("[-] URI syntax error.");
            }
        }
        return null;
    }

    /**
     * Make sure the found subdomain does not match (www.'request domain') or request domain or root domain
     */
    public static boolean isMatchedDomainValid(String matchedDomain, String rootDomain, String requestDomain) {
        return !matchedDomain.equals("www." + requestDomain)
                && !matchedDomain.equals(requestDomain)
                && !matchedDomain.equals("www." + rootDomain)
                && matchedDomain.endsWith(rootDomain);
    }

    public static boolean isHighEntropy(String s) {
        return Utilities.getShannonEntropy(s) >= 3.5;
    }

    // Source: https://rosettacode.org/wiki/Entropy#Java
    @SuppressWarnings("boxing")
    public static double getShannonEntropy(String s) {
        int n = 0;
        Map<Character, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < s.length(); ++c_) {
            char cx = s.charAt(c_);
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }
        double e = 0.0;
        for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
            if (n != 0) {
                double p = (double) entry.getValue() / n;
                e += p * log2(p);
            }
        }
        return -e;
    }

    private static double log2(double a) {
        return Math.log(a) / Math.log(2);
    }

    /**
     * Source: https://github.com/PortSwigger/example-scanner-checks/blob/master/java/BurpExtender.java
     * helper method to search a response for occurrences of a literal match string
     * and return a list of start/end offsets
     */
    public static List<Marker> getMatches(ByteArray response, byte[] match) {
        List<Marker> matches = new ArrayList<>();
        ByteArray matchByteArray = ByteArray.byteArray(match);

        int start = 0;
        while (start < response.length()) {
            start = response.indexOf(matchByteArray, true, start, response.length());
            if (start == -1)
                break;
            matches.add(Marker.marker(start, start + matchByteArray.length()));
            start += matchByteArray.length();
        }

        return matches;
    }

    public static Path handleDuplicateFile(Path originalFilePath) {
        if (Files.exists(originalFilePath)) {
            Matcher matcherFileName = FILE_NAME_REGEX.matcher(originalFilePath.toString());
            if (
                    matcherFileName.find()
                            && !matcherFileName.group(1).isEmpty()
                            && !matcherFileName.group(2).isEmpty()
            ) {
                String fileName = matcherFileName.group(1);
                String fileExtension = matcherFileName.group(2);
                return findValidName(originalFilePath, fileName, fileExtension);
            } else {
                return Paths.get(originalFilePath.getParent().toString())
                        .resolve(originalFilePath + "_copy");
            }
        }
        return originalFilePath;
    }

    private static Path findValidName(Path originalFilePath, String fileName, String fileExtension) {
        // To maintain performance, we will only handle 20 duplicate file names
        for (int i = 1; i < 20; i++) {
            if (!Files.exists(
                    Paths.get(originalFilePath.getParent().toString()) // get parent directory
                            .resolve(fileName + "_" + i + "." + fileExtension) // append suffix
            )) {
                return Paths.get(originalFilePath.getParent().toString()) // get parent directory
                        .resolve(fileName + "_" + i + "." + fileExtension); // append suffix
            }
        }
        return null;
    }

    public static void createDirectoriesIfNotExist(Path directoryPath) {
        if (!Files.exists(directoryPath)) {
            try {
                Files.createDirectories(directoryPath);
            } catch (IOException ioException) {
                mStdErr.println("[-] createDirectoriesIfNotExist IOException.");
            }
        }
    }

    public static boolean isDirEmpty(Path directory) {
        try (DirectoryStream<Path> dirStream = Files.newDirectoryStream(directory)) {
            return !dirStream.iterator().hasNext();
        } catch (IOException e) {
            return false;
        }
    }

    public static String getURL(URL url) {
        String urlString = url.toString();
        if (url.getDefaultPort() == url.getPort()) { // https://example.com:443/index -> https://example.com/index
            urlString = urlString.replaceFirst(":" + url.getPort(), "");
        }
        return urlString;
    }

    // get URL Prefix without query strings (to use with "getScanIssues")
    public static String getURLPrefix(URL url) {
        if (url.getDefaultPort() == url.getPort()) {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    url.getPath();
        } else {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    ":" +
                    url.getPort() +
                    url.getPath();
        }
    }

    public static String getURLPrefix(HttpRequestResponse httpRequestResponse) {
        return getURLPrefix(toURL(httpRequestResponse.request().url()));
    }

    public static String appendURLPath(URL url, String appendedPath) {
        if ((url.getProtocol().equalsIgnoreCase("https") && url.getPort() == 443)
                || (url.getProtocol().equalsIgnoreCase("http") && url.getPort() == 80)
        ) {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    url.getPath() + appendedPath;
        } else {
            return url.getProtocol() + "://" +
                    url.getHost() +
                    ":" +
                    url.getPort() +
                    url.getPath() + appendedPath;
        }
    }

    public static Path urlToPath(URI uri) {

        Path newPath = Paths.get(FileSystems.getDefault().getSeparator());

        String[] uriPaths = uri.getPath().split("/");
        for (String uriPath: uriPaths) {
            newPath = Paths.get( newPath.toUri() )
                    .resolve(uriPath);
        }

        return newPath;
    }

    public static String b64Decode(String encodedString) {
        byte[] decodedBytes = Base64.getDecoder().decode(encodedString.trim());
        return new String(decodedBytes);
    }

    public static boolean isValidBase64(String base64) {
        try {
            // Decode string
            Base64.getDecoder().decode(base64);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

}
