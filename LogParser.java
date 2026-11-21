import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;

/** Reads a CSV log file and turns each line into a LogEvent. */
public class LogParser {

    public static List<LogEvent> parse(String path) throws IOException {
        List<LogEvent> events = new ArrayList<>();
        try (BufferedReader reader = new BufferedReader(new FileReader(path))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("timestamp")) {
                    continue; // skip blank lines and the header
                }
                String[] parts = line.split(",");
                if (parts.length != 4) {
                    System.out.println("Skipping malformed line: " + line);
                    continue;
                }
                try {
                    LocalDateTime time = LocalDateTime.parse(parts[0].trim(), LogEvent.FORMAT);
                    boolean ok = parts[3].trim().equalsIgnoreCase("SUCCESS");
                    events.add(new LogEvent(time, parts[1].trim(), parts[2].trim(), ok));
                } catch (Exception e) {
                    System.out.println("Skipping unparsable line: " + line);
                }
            }
        }
        events.sort(Comparator.comparing(LogEvent::getTimestamp));
        return events;
    }
}
