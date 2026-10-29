package burp.core.scanners;

import burp.BurpExtender;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.utils.SourceMapper;
import burp.utils.Utilities;
import com.google.re2j.Matcher;

import java.net.MalformedURLException;
import java.net.URL;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

import static burp.BurpExtender.mStdErr;
import static burp.utils.Constants.b64SourceMapRegex;

public class InlineSourceMapFiles implements Runnable{
    private final HttpRequestResponse baseRequestResponse;
    private final Path outputDirectory;
    private final UUID taskUUID;

    public InlineSourceMapFiles(HttpRequestResponse baseRequestResponse, UUID taskUUID, long timeStamp) {
        this.baseRequestResponse = baseRequestResponse;
        this.outputDirectory = Paths.get(System.getProperty("user.home"))
                .resolve(".BurpSuite")
                .resolve("JS-Miner")
                .resolve(getRequestHost(baseRequestResponse) + "-" + timeStamp);
        this.taskUUID = taskUUID;
    }

    private static String getRequestHost(HttpRequestResponse baseRequestResponse) {
        try {
            return new URL(baseRequestResponse.request().url()).getHost();
        } catch (MalformedURLException e) {
            mStdErr.println("[-] MalformedURLException");
            return "unknown";
        }
    }

    @Override
    public void run() {
        BurpExtender.getTaskRepository().startTask(taskUUID);

        String responseBodyString = baseRequestResponse.response().body().toString();

        Matcher b64SourceMapperMatcher = b64SourceMapRegex.matcher(responseBodyString);

        while (b64SourceMapperMatcher.find()) {
            new SourceMapper(
                    baseRequestResponse,
                    Utilities.b64Decode(b64SourceMapperMatcher.group(3)), // Base64 Decoded map File Data
                    outputDirectory
            );
        }
        BurpExtender.getTaskRepository().completeTask(taskUUID);
    }
}
