package burp.core.scanners;

import burp.BurpExtender;
import burp.api.montoya.core.Marker;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.utils.Utilities;
import com.google.re2j.Matcher;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static burp.utils.Constants.*;
import static burp.utils.Utilities.appendFoundMatches;
import static burp.utils.Utilities.sendNewIssue;

public class CloudURLs implements Runnable {
    private final HttpRequestResponse baseRequestResponse;
    private final UUID taskUUID;

    public CloudURLs(HttpRequestResponse baseRequestResponse, UUID taskUUID) {
        this.baseRequestResponse = baseRequestResponse;
        this.taskUUID = taskUUID;
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);

        // For reporting unique matches with markers
        List<byte[]> uniqueMatches = new ArrayList<>();
        StringBuilder uniqueMatchesSB = new StringBuilder();

        String responseBodyString = baseRequestResponse.response().body().toString();

        Matcher cloudURLsMatcher = CLOUD_URLS_REGEX.matcher(responseBodyString);

        while (cloudURLsMatcher.find() && BurpExtender.isLoaded()) {
            uniqueMatches.add(cloudURLsMatcher.group().getBytes(StandardCharsets.UTF_8));
            appendFoundMatches(cloudURLsMatcher.group(), uniqueMatchesSB);
        }

        reportFinding(baseRequestResponse, uniqueMatchesSB, uniqueMatches);

        BurpExtender.getTaskRepository().completeTask(taskUUID);

    }

    private static void reportFinding(HttpRequestResponse baseRequestResponse, StringBuilder allMatchesSB, List<byte[]> uniqueMatches) {
        if (allMatchesSB.length() > 0) {
            // Get markers of found Cloud URL Matches
            List<Marker> allMatchesMarkers = Utilities.getMatches(baseRequestResponse.response().toByteArray(), uniqueMatches);

            // report the issue
            sendNewIssue(baseRequestResponse,
                    "[JS Miner] Cloud Resources",
                    "The following cloud URLs were found in a static file.",
                    allMatchesSB.toString(),
                    allMatchesMarkers,
                    SEVERITY_INFORMATION,
                    CONFIDENCE_CERTAIN
            );
        }
    }
}
