package burp.core;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.core.scanners.*;
import burp.utils.Utilities;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static burp.BurpExtender.mStdErr;
import static burp.BurpExtender.mStdOut;
import static burp.utils.Constants.*;


/**
 * Class to build and run specific scans. It also feeds data to TaskRepository.
 */
public class ScannerBuilder {
    private static final String[] EXTENSION_JS = {"js"};
    private static final String[] EXTENSION_JS_JSON = {"js", "json"};
    private static final String[] EXTENSION_CSS = {"css"};
    private static final String[] EXTENSION_JS_JSON_CSS_MAP = {"js", "json", "css", "map"};
    private static final MontoyaApi api = BurpExtender.getApi();

    private final List<HttpRequestResponse> baseRequestResponseArray;
    private final int taskId;
    private final long timeStamp;
    private final boolean scanSecrets;
    private final boolean scanDependencyConfusion;
    private final boolean scanCloudURLs;
    private final boolean scanSubDomains;
    private final boolean scanInlineSourceMapFiles;
    private final boolean activeSourceMapperScan;
    private final boolean dumpStaticFiles;
    private final boolean endpointsFinder;


    public static class Builder {
        // Required parameters
        private final List<HttpRequestResponse> baseRequestResponseArray;

        // Optional parameters - initialized to default values
        private long timeStamp = Instant.now().toEpochMilli();
        private int taskId = -1;
        private boolean scanSecrets = false;
        private boolean scanDependencyConfusion = false;
        private boolean scanCloudURLs = false;
        private boolean scanSubDomains = false;
        private boolean scanInlineSourceMapFiles = false;
        private boolean activeSourceMapperScan = false;
        private boolean dumpStaticFiles = false;
        private boolean endpointsFinder = false;

        public Builder(List<HttpRequestResponse> baseRequestResponseArray) {
            this.baseRequestResponseArray = baseRequestResponseArray;
        }

        public Builder taskId(int id) {
            taskId = id;
            return this;
        }

        public Builder scanSecrets() {
            scanSecrets = true;
            return this;
        }

        public Builder scanDependencyConfusion() {
            scanDependencyConfusion = true;
            return this;
        }

        public Builder scanCloudURLs() {
            scanCloudURLs = true;
            return this;
        }

        public Builder scanSubDomains() {
            scanSubDomains = true;
            return this;
        }

        public Builder scanInlineSourceMapFiles() {
            scanInlineSourceMapFiles = true;
            return this;
        }

        public Builder activeSourceMapperScan() {
            activeSourceMapperScan = true;
            return this;
        }

        public Builder timeStamp(long ts) {
            timeStamp = ts;
            return this;
        }

        public Builder dumpStaticFiles() {
            dumpStaticFiles = true;
            return this;
        }

        public Builder endpointsFinder() {
            endpointsFinder = true;
            return this;
        }

        public Builder runAllPassiveScans() {
            scanDependencyConfusion = true;
            scanSubDomains = true;
            scanSecrets = true;
            scanCloudURLs = true;
            scanInlineSourceMapFiles = true;
            endpointsFinder = true;
            return this;
        }

        public Builder runAllScans() {
            runAllPassiveScans();
            activeSourceMapperScan();
            return this;
        }

        public ScannerBuilder build() {
            return new ScannerBuilder(this);
        }
    }

    private ScannerBuilder(Builder builder) {
        baseRequestResponseArray = builder.baseRequestResponseArray;
        taskId = builder.taskId;
        timeStamp = builder.timeStamp;
        scanSecrets = builder.scanSecrets;
        scanDependencyConfusion = builder.scanDependencyConfusion;
        scanCloudURLs = builder.scanCloudURLs;
        scanSubDomains = builder.scanSubDomains;
        scanInlineSourceMapFiles = builder.scanInlineSourceMapFiles;
        activeSourceMapperScan = builder.activeSourceMapperScan;
        dumpStaticFiles = builder.dumpStaticFiles;
        endpointsFinder = builder.endpointsFinder;
    }

    public void runScans() {
        if (scanSecrets) {
            runSecretsScan(baseRequestResponseArray, taskId, timeStamp);
        }

        if (scanDependencyConfusion) {
            runDependencyConfusionScan(baseRequestResponseArray, taskId, timeStamp);
        }

        if (scanCloudURLs) {
            runCloudURLsScan(baseRequestResponseArray, taskId, timeStamp);
        }

        if (scanSubDomains) {
            runSubDomainsScan(baseRequestResponseArray, taskId, timeStamp);
        }

        if (scanInlineSourceMapFiles) {
            runInlineSourceMapper(baseRequestResponseArray, taskId, timeStamp);
        }

        if (activeSourceMapperScan) {
            runActiveSourceMapper(baseRequestResponseArray, taskId, timeStamp);
        }

        if (dumpStaticFiles) {
            runStaticFilesDumper(baseRequestResponseArray, taskId, timeStamp);
        }

        if (endpointsFinder) {
            runEndpointsFinder(baseRequestResponseArray, taskId, timeStamp);
        }
    }

    private static void scanVerifierExecutor(HttpRequestResponse requestResponse, int taskId, TaskName taskName, long timeStamp, boolean isLastIterator) {
        String url = requestResponse.request().url();
        byte[] responseBodyHash = Utilities.getHTTPResponseBodyHash(requestResponse);
        // Checks if Request URL & Response Body Hash were not scanned before
        if (BurpExtender.getTaskRepository().notDuplicate(taskName, url, responseBodyHash)) {
            UUID uuid = UUID.randomUUID();
            // New queued task
            BurpExtender.getTaskRepository().addTask(
                    new Task(taskId, uuid, taskName, url, responseBodyHash)
            );
            Runnable scanner = buildScanner(taskName, requestResponse, uuid, timeStamp, isLastIterator, true);
            if (scanner != null) {
                BurpExtender.getExecutorServiceManager().getExecutorService().submit(scanner);
            }
        } else {
            // Log skipped task to console
            logSkippedScanInfo(taskId, taskName, url);
        }
    }

    /*
     *  Passive scan check (invoked synchronously by Burp's passive audit).
     *  Only the message provided by the audit is analyzed and no new HTTP requests are made,
     *  as required for a PassiveScanCheck. Findings are reported through the check's
     *  AuditResult (see Utilities.beginIssueCollection) - the Dashboard integrated path.
     */
    public static void runPassiveScansSynchronously(HttpRequestResponse requestResponse) {
        if (!BurpExtender.isLoaded() || !requestResponse.hasResponse()) {
            return;
        }
        String path = requestResponse.request().pathWithoutQuery();
        boolean isJs = path.endsWith(".js");
        boolean isJson = path.endsWith(".json");
        boolean isCss = path.endsWith(".css");
        // HTML is detected by the response's Content-Type (not just the ".html" extension),
        // so extensionless HTML pages are covered as well.
        boolean isHtml = Utilities.isHTMLResponse(requestResponse);

        if (!isJs && !isJson && !isCss && !isHtml) {
            return;
        }

        long ts = Instant.now().toEpochMilli();

        if (isJs || isJson) {
            runInlineScan(requestResponse, TaskName.SECRETS_SCAN, ts);
            runInlineScan(requestResponse, TaskName.DEPENDENCY_CONFUSION_SCAN, ts);
            runInlineScan(requestResponse, TaskName.CLOUD_URLS_SCAN, ts);
            runInlineScan(requestResponse, TaskName.SUBDOMAINS_SCAN, ts);
        }
        if (isHtml) {
            // HTML responses are scanned for secrets only, using the exact same logic as JS files
            runInlineScan(requestResponse, TaskName.SECRETS_SCAN, ts);
        }
        if (isCss) {
            // CSS files are only checked for disclosed NPM package names (e.g. '/node_modules/<pkg>')
            runInlineScan(requestResponse, TaskName.DEPENDENCY_CONFUSION_SCAN_2, ts);
        }
        if (isJs) {
            runInlineScan(requestResponse, TaskName.INLINE_JS_SOURCE_MAPPER, ts);
            runInlineScan(requestResponse, TaskName.ENDPOINTS_FINDER, ts);
        }
    }

    private static void runInlineScan(HttpRequestResponse requestResponse, TaskName taskName, long timeStamp) {
        String url = requestResponse.request().url();
        byte[] responseBodyHash = Utilities.getHTTPResponseBodyHash(requestResponse);
        // Checks if Request URL & Response Body Hash were not scanned before
        if (BurpExtender.getTaskRepository().notDuplicate(taskName, url, responseBodyHash)) {
            UUID uuid = UUID.randomUUID();
            BurpExtender.getTaskRepository().addTask(new Task(-1, uuid, taskName, url, responseBodyHash));
            // Registry verification is disabled here: a passive scan check must not make new HTTP requests
            Runnable scanner = buildScanner(taskName, requestResponse, uuid, timeStamp, false, false);
            if (scanner != null) {
                try {
                    scanner.run();
                } catch (Exception e) {
                    // Fail the task so the file can be re-scanned in future audits
                    BurpExtender.getTaskRepository().failTask(uuid);
                    mStdErr.println("[-] Passive scan " + taskName + " failed for " + url + ": " + e.getMessage());
                }
            }
        }
    }

    private static Runnable buildScanner(TaskName taskName, HttpRequestResponse requestResponse, UUID uuid, long timeStamp, boolean isLastIterator, boolean verifyDependencyConfusion) {
        switch (taskName) {
            case SECRETS_SCAN:
                return new Secrets(requestResponse, uuid);
            case DEPENDENCY_CONFUSION_SCAN:
                return new DependencyConfusion(requestResponse, uuid, true, verifyDependencyConfusion);
            case DEPENDENCY_CONFUSION_SCAN_2:
                return new DependencyConfusion(requestResponse, uuid, false, verifyDependencyConfusion);
            case SUBDOMAINS_SCAN:
                return new SubDomains(requestResponse, uuid);
            case CLOUD_URLS_SCAN:
                return new CloudURLs(requestResponse, uuid);
            case INLINE_JS_SOURCE_MAPPER:
                return new InlineSourceMapFiles(requestResponse, uuid, timeStamp);
            case SOURCE_MAPPER_ACTIVE_SCAN:
                return new ActiveSourceMapper(requestResponse, timeStamp, uuid);
            case STATIC_FILES_DUMPER:
                return new StaticFilesDumper(requestResponse, timeStamp, uuid, isLastIterator);
            case ENDPOINTS_FINDER:
                return new Endpoints(requestResponse, uuid);
            default:
                return null;
        }
    }

    private static void runSecretsScan(List<HttpRequestResponse> baseRequestResponseArray, int taskId, long timeStamp) {
        // Scan JS/JSON files (as before) and HTML responses. HTML is detected by the response's
        // Content-Type (not just the ".html" extension), so extensionless HTML pages are covered too.
        List<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(
                baseRequestResponseArray,
                requestResponse -> Utilities.isValidScanTarget(requestResponse, EXTENSION_JS_JSON)
                        || Utilities.isHTMLResponse(requestResponse)
        );
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.SECRETS_SCAN, timeStamp, false);
        }
    }

    private static void runDependencyConfusionScan(List<HttpRequestResponse> baseRequestResponseArray, int taskId, long timeStamp) {
        // run Dependency Confusion Regex for all JS/JSON files
        List<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS_JSON);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.DEPENDENCY_CONFUSION_SCAN, timeStamp, false);
        }

        // For CSS files, don't run the regex (only check for disclosures like in '/node_modules/<pkg>')
        List<HttpRequestResponse> uniqueRequestsCSS = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_CSS);
        for (HttpRequestResponse requestResponse : uniqueRequestsCSS) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.DEPENDENCY_CONFUSION_SCAN_2, timeStamp, false);
        }
    }

    private static void runCloudURLsScan(List<HttpRequestResponse> baseRequestResponseArray, int taskId, long timeStamp) {
        List<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS_JSON);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.CLOUD_URLS_SCAN, timeStamp, false);
        }
    }

    private static void runSubDomainsScan(List<HttpRequestResponse> baseRequestResponseArray, int taskId, long timeStamp) {
        List<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS_JSON);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.SUBDOMAINS_SCAN, timeStamp, false);
        }
    }

    private static void runInlineSourceMapper(List<HttpRequestResponse> baseRequestResponseArray, int taskId, long timeStamp) {
        List<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.INLINE_JS_SOURCE_MAPPER, timeStamp, false);
        }
    }

    private static void runActiveSourceMapper(List<HttpRequestResponse> baseRequestResponseArray, int taskId, long timeStamp) {
        List<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.SOURCE_MAPPER_ACTIVE_SCAN, timeStamp, false);
        }
    }

    private static void runStaticFilesDumper(List<HttpRequestResponse> baseRequestResponseArray, int taskId, long timeStamp) {
        List<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS_JSON_CSS_MAP);
        for (int i = 0; i < uniqueRequests.size(); i++) {
            HttpRequestResponse httpRequestResponse = uniqueRequests.get(i);
            boolean isLastIterator = i == uniqueRequests.size() - 1;
            scanVerifierExecutor(httpRequestResponse, taskId, TaskName.STATIC_FILES_DUMPER, timeStamp, isLastIterator);
        }
    }

    private static void runEndpointsFinder(List<HttpRequestResponse> baseRequestResponseArray, int taskId, long timeStamp) {
        List<HttpRequestResponse> uniqueRequests = Utilities.querySiteMap(baseRequestResponseArray, EXTENSION_JS);
        for (HttpRequestResponse requestResponse : uniqueRequests) {
            scanVerifierExecutor(requestResponse, taskId, TaskName.ENDPOINTS_FINDER, timeStamp, false);
        }
    }


    @Override
    public String toString() {
        return "Scan Information{" +
                "RequestURL=" + Utilities.getURLPrefix(baseRequestResponseArray.get(0)) +
                ", taskId=" + taskId +
                ", timeStamp=" + timeStamp +
                ", scanSecrets=" + scanSecrets +
                ", scanDependencyConfusion=" + scanDependencyConfusion +
                ", scanCloudURLs=" + scanCloudURLs +
                ", scanSubDomains=" + scanSubDomains +
                ", scanInlineSourceMapFiles=" + scanInlineSourceMapFiles +
                ", activeSourceMapperScan=" + activeSourceMapperScan +
                '}';
    }

    private static void logSkippedScanInfo(int taskId, TaskName scannerName, String url) {
        if (taskId != -1 && BurpExtender.getExtensionConfig().isVerboseLogging()) {
            mStdOut.printf(LOG_FORMAT, "[" + TaskStatus.SKIPPED + "]", LOG_TASK_ID_PREFIX + taskId, scannerName, url);
        }
    }

}
