import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * Entry point.
 * Usage:  java Main                 (generates sample_logs.csv if missing)
 *         java Main my_logs.csv     (analyses your own log file)
 */
public class Main {

    public static void main(String[] args) throws IOException {
        String path = args.length > 0 ? args[0] : "sample_logs.csv";

        if (!new File(path).exists()) {
            LogGenerator.generate(path);
            System.out.println("Generated sample log file: " + path);
        }

        List<LogEvent> events = LogParser.parse(path);
        System.out.println("Loaded " + events.size() + " log events.\n");

        // To add a new rule, write a class that implements Detector and add it here.
        List<Detector> detectors = Arrays.asList(
                new BruteForceDetector(5, 60),   // 5 fails within 60 seconds
                new OddHourDetector(6, 22),      // logins before 6 AM or after 10 PM
                new AccountSpreadDetector(4),    // one user, 4+ different IPs
                new StatDetector(2.0)            // z-score of 2 or more
        );

        List<Alert> alerts = new ArrayList<>();
        for (Detector d : detectors) {
            alerts.addAll(d.detect(events));
        }
        Collections.sort(alerts); // HIGH risk first

        System.out.println("===== ALERT REPORT (" + alerts.size() + " alerts) =====");
        for (Alert a : alerts) {
            System.out.println(a);
        }

        try (PrintWriter out = new PrintWriter(new FileWriter("alerts_report.txt"))) {
            out.println("ALERT REPORT (" + alerts.size() + " alerts)");
            for (Alert a : alerts) {
                out.println(a);
            }
        }
        System.out.println("\nReport saved to alerts_report.txt");
    }
}
