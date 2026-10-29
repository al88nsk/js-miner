package burp.core.scanners;

import burp.BurpExtender;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.utils.SourceMapper;
import burp.utils.Utilities;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import static burp.BurpExtender.mStdErr;

public class ActiveSourceMapper implements Runnable {
    private static final MontoyaApi api = BurpExtender.getApi();
    private URL jsMapURL;
    private Path outputDirectory;
    private final UUID taskUUID;

    public ActiveSourceMapper(HttpRequestResponse requestResponse, long currentTimestamp, UUID taskUUID) {
        URL jsURL;
        this.taskUUID = taskUUID;

        try {
            jsURL = new URL(requestResponse.request().url());
            this.jsMapURL = new URL(Utilities.appendURLPath(jsURL, ".map"));
            this.outputDirectory = Paths.get(System.getProperty("user.home"))
                    .resolve(".BurpSuite")
                    .resolve("JS-Miner")
                    .resolve(jsMapURL.getHost() + "-" + currentTimestamp);
        } catch (MalformedURLException e) {
            mStdErr.println("[-] MalformedURLException");
        }
    }

    public void run() {
        try {
            BurpExtender.getTaskRepository().startTask(taskUUID);
            HttpRequestResponse newHTTPReqRes = api.http().sendRequest(HttpRequest.httpRequestFromUrl(jsMapURL.toString()));
            // if 200 OK, add to sitemap & pass content to parse map files
            if (newHTTPReqRes.hasResponse()
                    && newHTTPReqRes.response().statusCode() == 200
                    && BurpExtender.isLoaded()
            ) {
                api.siteMap().add(newHTTPReqRes);
                String responseBody = newHTTPReqRes.response().body().toString();
                // Quick check to see if Response contains what we are looking for
                if (responseBody.contains("sources") && responseBody.contains("sourcesContent")) {
                    new SourceMapper(
                            newHTTPReqRes,
                            responseBody,
                            outputDirectory
                    );
                }
            }
            BurpExtender.getTaskRepository().completeTask(taskUUID);
        } catch (Exception e) {
            BurpExtender.getTaskRepository().failTask(taskUUID);
            StackTraceElement[] traces = e.getStackTrace();
            for (StackTraceElement trace : traces) {
                mStdErr.println(trace);
            }
        }
    }
}
