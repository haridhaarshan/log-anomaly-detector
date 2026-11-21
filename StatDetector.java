import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Statistical anomaly detection.
 * Counts login attempts per IP, then flags any IP whose count is far above
 * the average. "Far above" is measured by the z-score:
 *
 *     z = (count - mean) / standardDeviation
 *
 * This catches unusual activity even when it breaks none of the fixed rules.
 */
public class StatDetector implements Detector {

    private final double zThreshold;

    public StatDetector(double zThreshold) {
        this.zThreshold = zThreshold;
    }

    @Override
    public List<Alert> detect(List<LogEvent> events) {
        Map<String, Integer> attemptsByIp = new HashMap<>();
        for (LogEvent e : events) {
            attemptsByIp.merge(e.getIp(), 1, Integer::sum);
        }

        List<Alert> alerts = new ArrayList<>();
        if (attemptsByIp.size() < 2) {
            return alerts; // not enough data to compare
        }

        // Mean
        double sum = 0;
        for (int c : attemptsByIp.values()) {
            sum += c;
        }
        double mean = sum / attemptsByIp.size();

        // Standard deviation
        double squares = 0;
        for (int c : attemptsByIp.values()) {
            squares += (c - mean) * (c - mean);
        }
        double std = Math.sqrt(squares / attemptsByIp.size());
        if (std == 0) {
            return alerts; // everyone behaves identically
        }

        for (Map.Entry<String, Integer> entry : attemptsByIp.entrySet()) {
            double z = (entry.getValue() - mean) / std;
            if (z >= zThreshold) {
                alerts.add(new Alert("Statistical outlier", Alert.Risk.MEDIUM,
                        String.format("%s made %d attempts (average %.1f, z-score %.2f)",
                                entry.getKey(), entry.getValue(), mean, z)));
            }
        }
        return alerts;
    }
}
