import java.time.Duration;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Flags an IP address that fails to log in too many times in a short window.
 * Uses a sliding window over each IP's failed-attempt timestamps.
 */
public class BruteForceDetector implements Detector {

    private final int threshold;        // failures needed to raise an alert
    private final long windowSeconds;   // length of the time window

    public BruteForceDetector(int threshold, long windowSeconds) {
        this.threshold = threshold;
        this.windowSeconds = windowSeconds;
    }

    @Override
    public List<Alert> detect(List<LogEvent> events) {
        // Group failed-attempt times by IP address
        Map<String, List<LocalDateTime>> failsByIp = new HashMap<>();
        for (LogEvent e : events) {
            if (!e.isSuccess()) {
                failsByIp.computeIfAbsent(e.getIp(), k -> new ArrayList<>())
                         .add(e.getTimestamp());
            }
        }

        List<Alert> alerts = new ArrayList<>();
        for (Map.Entry<String, List<LocalDateTime>> entry : failsByIp.entrySet()) {
            List<LocalDateTime> times = entry.getValue();
            Collections.sort(times);

            // Sliding window: find the most failures inside any one window
            int start = 0;
            int maxInWindow = 0;
            for (int end = 0; end < times.size(); end++) {
                while (Duration.between(times.get(start), times.get(end)).getSeconds()
                        > windowSeconds) {
                    start++;
                }
                maxInWindow = Math.max(maxInWindow, end - start + 1);
            }

            if (maxInWindow >= threshold) {
                Alert.Risk risk = (maxInWindow >= threshold * 2)
                        ? Alert.Risk.HIGH : Alert.Risk.MEDIUM;
                alerts.add(new Alert("Brute force", risk,
                        entry.getKey() + " had " + maxInWindow + " failed logins within "
                        + windowSeconds + " seconds"));
            }
        }
        return alerts;
    }
}
