package burp.core.scanners;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.utils.NPMPackage;
import burp.utils.Utilities;
import com.google.re2j.Matcher;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.UUID;

import static burp.utils.Constants.*;
import static burp.utils.Utilities.*;

public class DependencyConfusion implements Runnable {
    private static final MontoyaApi api = BurpExtender.getApi();
    private final HttpRequestResponse baseRequestResponse;
    private final UUID taskUUID;
    private final boolean findDependenciesWithRegex;
    private final boolean verifyWithRegistry;

    public DependencyConfusion(HttpRequestResponse baseRequestResponse, UUID taskUUID, boolean findDependenciesWithRegex, boolean verifyWithRegistry) {
        this.baseRequestResponse = baseRequestResponse;
        this.taskUUID = taskUUID;
        this.findDependenciesWithRegex = findDependenciesWithRegex;
        this.verifyWithRegistry = verifyWithRegistry;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);

        // For reporting unique matches with markers
        List<byte[]> uniqueMatches = new ArrayList<>();
        StringBuilder uniqueMatchesSB = new StringBuilder();

        String responseBodyString = baseRequestResponse.response().body().toString();

        // Removing unwanted spaces, new lines and so on, which might mislead matching our Regex
        Matcher dependenciesListMatcher = EXTRACT_DEPENDENCIES_REGEX.matcher(responseBodyString
                .replaceAll("\\s", "")
                .replace("\t", "")
                .replace("\r", "")
                .replace("\n", ""));

        HashSet<NPMPackage> uniquePackageNames = new HashSet<>();

        // Approach 1 to identify internal NPM packages based on the "EXTRACT_DEPENDENCIES_REGEX"
        if (findDependenciesWithRegex) {
            while (dependenciesListMatcher.find()) {
                String dependencyList = dependenciesListMatcher.group(2);
                String[] dependencyListArray = dependencyList.split(",");
                for (String dependency : dependencyListArray) {
                    // A new npm package that holds and validates name and version for later use
                    NPMPackage npmPackage = new NPMPackage(dependency);

                    // package name must be valid
                    if (npmPackage.isNameValid()) {
                        uniquePackageNames.add(npmPackage);
                        uniqueMatches.add(npmPackage.getNameWithVersion().getBytes());
                        appendFoundMatches(npmPackage.getNameWithVersion(), uniqueMatchesSB);
                    }
                }
            }
        }

        // Approach 2 to identify internal NPM packages that were part of common node_modules URL path (e.g.: /node_modules/<pkg> )
        Matcher fromNodeModulesPathMatcher = extractFromNodeModules.matcher(responseBodyString);
        while (fromNodeModulesPathMatcher.find()) {
            // The new npm package won't have a version, so passing "disclosedNameOnly" flag to handle it properly
            NPMPackage npmPackage = new NPMPackage(fromNodeModulesPathMatcher.group(1), true);
            // package name must be valid
            if (npmPackage.isNameValid()) {
                uniquePackageNames.add(npmPackage);
                uniqueMatches.add(npmPackage.getNameWithVersion().getBytes());
                appendFoundMatches(npmPackage.getNameWithVersion(), uniqueMatchesSB);
            }
        }

        // Get matches & report all dependencies as info
        if (uniqueMatchesSB.length() > 0) {
            List<Marker> allDependenciesMatches = getMatches(baseRequestResponse.response().toByteArray(), uniqueMatches);
            reportDependencies(baseRequestResponse, uniqueMatchesSB.toString(), allDependenciesMatches);

            if (verifyWithRegistry) {
                // Loop each identified package and check for Dependency Confusion
                for (NPMPackage npmPackage : uniquePackageNames) {
                    // Get markers of each single dependency with its version
                    List<Marker> depMatches = getMatches(baseRequestResponse.response().toByteArray(), npmPackage.toString().getBytes());
                    try {
                        if (isConnectionOK()) {
                            verifyDependencyConfusion(baseRequestResponse, npmPackage, depMatches);
                            BurpExtender.getTaskRepository().completeTask(taskUUID);
                        } else {
                            // If connection failed, fail the task to allow re-scanning
                            BurpExtender.getTaskRepository().failTask(taskUUID);
                        }
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
            } else {
                // Registry verification is skipped (e.g. for the passive scan check, which must
                // not make new HTTP requests of its own). Dependencies are reported as info only;
                // the full "Dependency Confusion" scan with npm verification is available from the
                // context menu.
                BurpExtender.getTaskRepository().completeTask(taskUUID);
            }
        } else {
            // if no NPM package names were found, then task is completed
            BurpExtender.getTaskRepository().completeTask(taskUUID);
        }
    }

    private static boolean isConnectionOK(){
        try {
            URL npmURL = new URL("https://www.npmjs.com/robots.txt");
            HttpRequestResponse npmJSReqRes = api.http().sendRequest(HttpRequest.httpRequestFromUrl(npmURL.toString()));
            URL npmRegistryURL = new URL("https://registry.npmjs.org/");
            HttpRequestResponse npmRegistryReqRes = api.http().sendRequest(HttpRequest.httpRequestFromUrl(npmRegistryURL.toString()));

            return npmJSReqRes.hasResponse() && npmRegistryReqRes.hasResponse();
        } catch (MalformedURLException e) {
            e.printStackTrace();
        }
        return false;
    }

    private static void reportDependencies(HttpRequestResponse baseRequestResponse, String dependenciesList, List<Marker> depMatches) {
        String findingTitle;
        String findingDetail;
        AuditIssueSeverity severity = SEVERITY_INFORMATION;

        findingTitle = "[JS Miner] Dependencies";
        findingDetail = "The following dependencies were found in a static file.";

        sendNewIssue(baseRequestResponse,
                findingTitle,
                findingDetail,
                dependenciesList,
                depMatches,
                severity,
                CONFIDENCE_CERTAIN
        );
    }

    // Verify if dependency is exploitable by querying npm js registry service
    private static void verifyDependencyConfusion(HttpRequestResponse baseRequestResponse, NPMPackage npmPackage, List<Marker> depMatches) throws IOException {
        String findingTitle = null;
        String findingDetail = null;
        AuditIssueSeverity severity = SEVERITY_INFORMATION;

        // 1. if package version does not comply with NPM Semantic versioning, then report it as info for manual analysis
        if (!npmPackage.isVersionValidNPM()) {
            findingTitle = "[JS Miner] Dependency (Non-NPM registry package)";
            findingDetail = "The following non-NPM dependency was found in a static file. The version might contain a public repository URL, a private repository URL or a file path. Manual review is advised.";
        } else if (npmPackage.getName().startsWith("@")) {
            // 2. if package name starts with "@", then it's a scoped package.
            String organizationName = npmPackage.getOrgNameFromScopedDependency();

            URL url = new URL("https://www.npmjs.com/org/" + organizationName);
            HttpRequestResponse httpRequestResponse = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url.toString()));

            // 2.1 scoped package with non-existing organization -> Most likely a valid issue
            if (httpRequestResponse.hasResponse()
                    && httpRequestResponse.response().statusCode() == 404) {
                // valid critical issue
                findingTitle = "[JS Miner] Dependency (organization not found)";
                findingDetail = "The following potentially exploitable dependency was found in a static file. The organization does not seem to be available, which indicates that it can be registered: " + url;
                severity = SEVERITY_HIGH;
            }
        } else {
            // 3. Public NPM package
            URL url = new URL("https://registry.npmjs.org/" + npmPackage.getName());
            HttpRequestResponse httpRequestResponse = api.http().sendRequest(HttpRequest.httpRequestFromUrl(url.toString()));

            // 3.1 If package name does not exist -> Most likely a valid issue
            if (httpRequestResponse.hasResponse()
                    && httpRequestResponse.response().statusCode() == 404) {
                // valid critical issue
                findingTitle = "[JS Miner] Dependency Confusion";
                findingDetail = "The following potentially exploitable dependency was found in a static file. There was no entry for this package on the 'npm js' registry: " + url;
                severity = SEVERITY_HIGH;
            }
        }

        if (findingTitle != null) {
            sendNewIssue(baseRequestResponse,
                    findingTitle,
                    findingDetail,
                    npmPackage.getNameWithVersion(),
                    depMatches,
                    severity,
                    CONFIDENCE_CERTAIN
            );
        }
    }
}
