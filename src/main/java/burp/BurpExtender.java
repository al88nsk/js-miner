package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.scancheck.PassiveScanCheck;
import burp.api.montoya.scanner.scancheck.ScanCheckType;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.config.ExecutorServiceManager;
import burp.config.ExtensionConfig;
import burp.core.ScannerBuilder;
import burp.core.TaskRepository;
import burp.utils.Utilities;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import static burp.utils.Constants.SETTING_BURP_PASSIVE;
import static burp.utils.Constants.SETTING_VERBOSE_LOGGING;

public class BurpExtender implements BurpExtension, ContextMenuItemsProvider {
    private static MontoyaApi api;
    private static final ExecutorServiceManager executorServiceManager = ExecutorServiceManager.getInstance();
    private static final TaskRepository taskRepository = TaskRepository.getInstance();
    private static final ExtensionConfig extensionConfig = ExtensionConfig.getInstance();
    private static boolean loaded = true;
    public static PrintWriter mStdOut;
    public static PrintWriter mStdErr;
    public static final String EXTENSION_NAME = "JS Miner";
    private static final String EXTENSION_VERSION = "2.0";
    private int taskCount = 0; // counter for invoked tasks through the menu items context (Not for Burp's passive scan)

    // Exposing the Montoya API for use in other classes
    public static MontoyaApi getApi() {
        return api;
    }

    public static boolean isLoaded() {
        return loaded;
    }

    public static void setLoaded(boolean loaded) {
        BurpExtender.loaded = loaded;
    }

    public static ExecutorServiceManager getExecutorServiceManager() {
        return executorServiceManager;
    }

    public static TaskRepository getTaskRepository() {
        return taskRepository;
    }

    public static ExtensionConfig getExtensionConfig() {
        return extensionConfig;
    }

    @Override
    @SuppressWarnings("deprecation") // Logging.output()/error() are deprecated in favour of logToOutput/logToError
    public void initialize(MontoyaApi api) {
        BurpExtender.api = api;
        // Extension initializations
        api.extension().setName(EXTENSION_NAME);

        // register ourselves as a custom scanner check (passive scans)
        registerPassiveScanCheck();

        // register a context menu items provider
        api.userInterface().registerContextMenuItemsProvider(this);

        // register an unloaded handler
        api.extension().registerUnloadingHandler(this::extensionUnloaded);

        // obtain our output and error streams
        mStdOut = new PrintWriter(api.logging().output(), true);
        mStdErr = new PrintWriter(api.logging().error(), true);

        mStdOut.println("[*] Loaded:\t" + EXTENSION_NAME + " v" + EXTENSION_VERSION);
        mStdOut.println("[*] Author:\tMina M. Edwar (minamo7sen@gmail.com)");
        mStdOut.println("=================================================");

        // Load extension configurations
        loadExtensionConfig();

    }

    private void registerPassiveScanCheck() {
        api.scanner().registerPassiveScanCheck(new PassiveScanCheck() {
            @Override
            public String checkName() {
                return EXTENSION_NAME + " passive checks";
            }

            @Override
            public AuditResult doCheck(HttpRequestResponse baseRequestResponse) {
                // The passive scans run synchronously here and report their findings through the
                // returned AuditResult - the path that integrates with Burp's user-driven workflow
                // (i.e. the Dashboard). Reporting out-of-band via SiteMap.add() is only intended for
                // porting results from other tools and does not surface issues on the Dashboard.
                if (!extensionConfig.isPassiveEnabled() || !isLoaded()) {
                    return AuditResult.auditResult();
                }
                Utilities.beginIssueCollection();
                try {
                    ScannerBuilder.runPassiveScansSynchronously(baseRequestResponse);
                } catch (Exception e) {
                    // Never let a passive scan error kill Burp's audit thread
                    mStdErr.println("[-] Passive scan error: " + e.getMessage());
                }
                return AuditResult.auditResult(Utilities.finishIssueCollection());
            }

            @Override
            public ConsolidationAction consolidateIssues(AuditIssue existingIssue, AuditIssue newIssue) {
                // Combine identical issues reported more than once for the same URL path
                // (e.g. when the same static file is re-audited)
                if (Objects.equals(existingIssue.name(), newIssue.name())
                        && Objects.equals(existingIssue.detail(), newIssue.detail())) {
                    return ConsolidationAction.KEEP_EXISTING;
                }
                return ConsolidationAction.KEEP_BOTH;
            }
        }, ScanCheckType.PER_REQUEST);
    }

    private void updateExtensionConfig() {
        api.persistence().preferences().setString(SETTING_VERBOSE_LOGGING, String.valueOf(extensionConfig.isVerboseLogging()));
        api.persistence().preferences().setString(SETTING_BURP_PASSIVE, String.valueOf(extensionConfig.isPassiveEnabled()));
    }

    public void loadExtensionConfig() {
        if (api.persistence().preferences().getString(SETTING_VERBOSE_LOGGING) != null) {
            extensionConfig.setVerboseLogging(Boolean.parseBoolean(api.persistence().preferences().getString(SETTING_VERBOSE_LOGGING)));
        }

        if (api.persistence().preferences().getString(SETTING_BURP_PASSIVE) != null) {
            extensionConfig.setPassiveEnabled(Boolean.parseBoolean(api.persistence().preferences().getString(SETTING_BURP_PASSIVE)));
        }

    }

    public void extensionUnloaded() {
        setLoaded(false);
        taskRepository.destroy();
        mStdOut.println("[*] Sending shutdown signal to terminate any running threads..");
        executorServiceManager.getExecutorService().shutdownNow();
        mStdOut.println("[*] Extension was unloaded.");
        mStdOut.println("=================================================");
    }

    /*
     *  Context menu items
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent invocation) {
        if (invocation.isFrom(
                InvocationType.SITE_MAP_TREE,
                InvocationType.SITE_MAP_TABLE,
                InvocationType.PROXY_HISTORY,
                InvocationType.MESSAGE_VIEWER_REQUEST,
                InvocationType.MESSAGE_VIEWER_RESPONSE,
                InvocationType.MESSAGE_EDITOR_REQUEST,
                InvocationType.MESSAGE_EDITOR_RESPONSE
        )) {
            List<HttpRequestResponse> selectedMessages = getSelectedMessages(invocation);
            if (selectedMessages.isEmpty()) {
                return null;
            }

            List<Component> items = new ArrayList<>();
            JMenu scanItems = new JMenu("Scans");
            JMenu logItems = new JMenu("Log");
            JMenu configItems = new JMenu("Config");

            // === Main Scans Menu Items ==== //
            JMenuItem autoMineItem = new JMenuItem("Run JS Auto-Mine (check everything)");
            JSAutoMineItemAction autoMineItemActionAction = new JSAutoMineItemAction(selectedMessages);
            autoMineItem.addActionListener(autoMineItemActionAction);
            items.add(autoMineItem);

            JMenuItem findInterestingStuffItem = new JMenuItem("Run all passive scans ");
            AllPassiveScansItemAction findStuffAction = new AllPassiveScansItemAction(selectedMessages);
            findInterestingStuffItem.addActionListener(findStuffAction);
            items.add(findInterestingStuffItem);

            // === Specific Scans Menu Items ==== //
            JMenuItem jsSourceMapItem = new JMenuItem("JS source mapper (active)");
            ActiveSourceMapsItemAction jsMapAction = new ActiveSourceMapsItemAction(selectedMessages);
            jsSourceMapItem.addActionListener(jsMapAction);
            scanItems.add(jsSourceMapItem);

            JMenuItem secretsMenuItem = new JMenuItem("Secrets");
            SecretsItemAction secretsItemAction = new SecretsItemAction(selectedMessages);
            secretsMenuItem.addActionListener(secretsItemAction);
            scanItems.add(secretsMenuItem);

            JMenuItem dependencyConfusionMenuItem = new JMenuItem("Dependency Confusion");
            DependencyConfusionItemAction dependencyConfusionItemAction = new DependencyConfusionItemAction(selectedMessages);
            dependencyConfusionMenuItem.addActionListener(dependencyConfusionItemAction);
            scanItems.add(dependencyConfusionMenuItem);

            JMenuItem subDomainsMenuItem = new JMenuItem("SubDomains");
            SubDomainsItemAction subDomainsItemAction = new SubDomainsItemAction(selectedMessages);
            subDomainsMenuItem.addActionListener(subDomainsItemAction);
            scanItems.add(subDomainsMenuItem);

            JMenuItem cloudURLsMenuItem = new JMenuItem("Cloud URLs");
            CloudURLsItemAction cloudURLsItemAction = new CloudURLsItemAction(selectedMessages);
            cloudURLsMenuItem.addActionListener(cloudURLsItemAction);
            scanItems.add(cloudURLsMenuItem);

            JMenuItem inlineSourceMapsMenuItem = new JMenuItem("Inline B64 JS Source Maps");
            InlineSourceMapsItemAction inlineSourceMapsItemAction = new InlineSourceMapsItemAction(selectedMessages);
            inlineSourceMapsMenuItem.addActionListener(inlineSourceMapsItemAction);
            scanItems.add(inlineSourceMapsMenuItem);

            JMenuItem dumpStaticFilesMenuItem = new JMenuItem("Dump Static Files");
            DumpStaticFilesItemAction dumpStaticFilesItemAction = new DumpStaticFilesItemAction(selectedMessages);
            dumpStaticFilesMenuItem.addActionListener(dumpStaticFilesItemAction);
            scanItems.add(dumpStaticFilesMenuItem);

            JMenuItem endpointsFinderMenuItem = new JMenuItem("API Endpoints Finder");
            EndpointsFinderItemAction endpointsFinderItemAction = new EndpointsFinderItemAction(selectedMessages);
            endpointsFinderMenuItem.addActionListener(endpointsFinderItemAction);
            scanItems.add(endpointsFinderMenuItem);

            // === Logging Menu Items ==== //
            JMenuItem checkTasksMenuItem = new JMenuItem("Tasks Summary");
            CheckTasksMenuItemActions checkTasksMenuItemActions = new CheckTasksMenuItemActions();
            checkTasksMenuItem.addActionListener(checkTasksMenuItemActions);
            logItems.add(checkTasksMenuItem);

            JMenuItem runningMenuItem = new JMenuItem("Log Uncompleted Tasks");
            PrintUncompletedTasksMenuItemActions runningTasksMenuItemActions = new PrintUncompletedTasksMenuItemActions();
            runningMenuItem.addActionListener(runningTasksMenuItemActions);
            logItems.add(runningMenuItem);

            // === Configuration Menu Items ==== //
            JMenuItem toggleLoggingMenuItem = new JMenuItem(extensionConfig.loggingConfigMenuItemText());
            ToggleLoggingMenuItemActions toggleLoggingMenuItemActions = new ToggleLoggingMenuItemActions();
            toggleLoggingMenuItem.addActionListener(toggleLoggingMenuItemActions);
            configItems.add(toggleLoggingMenuItem);

            JMenuItem toggleBurpPassiveScanMenuItem = new JMenuItem(extensionConfig.passiveConfigMenuItemText());
            ToggleBurpPassiveMenuItemActions toggleBurpPassiveMenuItemActions = new ToggleBurpPassiveMenuItemActions();
            toggleBurpPassiveScanMenuItem.addActionListener(toggleBurpPassiveMenuItemActions);
            configItems.add(toggleBurpPassiveScanMenuItem);

            items.add(configItems);
            items.add(scanItems);
            items.add(logItems);

            return items;
        }
        return null;
    }

    /*
     *  Get the selected HTTP messages for the current context menu invocation.
     *  For the message viewer/editor contexts, the message being displayed is used.
     */
    private static List<HttpRequestResponse> getSelectedMessages(ContextMenuEvent invocation) {
        if (invocation.messageEditorRequestResponse().isPresent()) {
            return Collections.singletonList(invocation.messageEditorRequestResponse().get().requestResponse());
        }
        return invocation.selectedRequestResponses();
    }

    /*
     *  Action menu items
     */
    class SecretsItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        SecretsItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanSecrets()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class DependencyConfusionItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        DependencyConfusionItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanDependencyConfusion()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class SubDomainsItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        SubDomainsItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanSubDomains()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class CloudURLsItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        CloudURLsItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanCloudURLs()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class InlineSourceMapsItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        InlineSourceMapsItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files (of the same host) can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .scanInlineSourceMapFiles()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class ActiveSourceMapsItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        ActiveSourceMapsItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .activeSourceMapperScan()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class JSAutoMineItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        JSAutoMineItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .runAllScans()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class AllPassiveScansItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        AllPassiveScansItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .runAllPassiveScans()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class DumpStaticFilesItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        DumpStaticFilesItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                // We need to use timestamp so all files can go to the same folder
                long ts = Instant.now().toEpochMilli();
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .dumpStaticFiles()
                        .taskId(++taskCount)
                        .timeStamp(ts)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class EndpointsFinderItemAction implements ActionListener {
        private final List<HttpRequestResponse> httpReqResArray;

        EndpointsFinderItemAction(List<HttpRequestResponse> httpReqResArr) {
            this.httpReqResArray = httpReqResArr;
        }

        @Override
        public void actionPerformed(ActionEvent e) {
            new Thread(() -> {
                ScannerBuilder scannerBuilder = new ScannerBuilder.Builder(httpReqResArray)
                        .endpointsFinder()
                        .taskId(++taskCount)
                        .build();
                scannerBuilder.runScans();
            }).start();
        }
    }

    class CheckTasksMenuItemActions implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            mStdOut.println("[=============== Tasks Summary =============]");
            mStdOut.println("Total Tasks: " + getTaskRepository().getSize());
            mStdOut.println("Queued tasks: " + taskRepository.getQueuedTasks().size());
            mStdOut.println("Completed tasks: " + taskRepository.getCompletedTasks().size());
            mStdOut.println("Running tasks: " + taskRepository.getRunningTasks().size());
            mStdOut.println("Failed tasks: " + taskRepository.getFailedTasks().size());
            mStdOut.println("============================================");
        }
    }

    class PrintUncompletedTasksMenuItemActions implements ActionListener {

        @Override
        public void actionPerformed(ActionEvent e) {
            mStdOut.println("[=============== Uncompleted Tasks =============]");

            int runningTasksSize = taskRepository.getRunningTasks().size();
            // If there was some timed out tasks, print them for troubleshooting or local checking
            if (runningTasksSize > 0) {
                mStdOut.println("Running tasks:" + taskRepository.printRunningTasks().toString());
                mStdOut.println("=============================================");
            }

            int failedTasksSize = taskRepository.getFailedTasks().size();
            // If there was some timed out tasks, print them for troubleshooting or local checking
            if (failedTasksSize > 0) {
                mStdOut.println("Failed tasks:" + taskRepository.printFailedTasks().toString());
                mStdOut.println("=============================================");
            }
        }
    }

    class ToggleLoggingMenuItemActions implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            extensionConfig.toggleLogging();
            updateExtensionConfig();
        }
    }

    class ToggleBurpPassiveMenuItemActions implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            extensionConfig.togglePassiveScans();
            updateExtensionConfig();
        }
    }
}
