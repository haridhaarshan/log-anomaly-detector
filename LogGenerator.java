import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Random;

/**
 * Creates a fake log file: mostly normal office activity,
 * with a few attacks hidden inside so the detectors have something to find.
 */
public class LogGenerator {

    public static void generate(String path) throws IOException {
        Random rnd = new Random(42); // fixed seed = same data every run
        LocalDate day = LocalDate.of(2026, 11, 20);
        List<LogEvent> events = new ArrayList<>();

        String[] users = {"priya", "arjun", "meena", "karthik", "divya", "suresh",
                "anita", "vikram", "lakshmi", "ravi", "nisha", "rahul"};

        // 1) Normal behaviour: each user logs in 3-6 times during office hours
        //    from their own machine, with an occasional typo (about 10% FAIL).
        for (int i = 0; i < users.length; i++) {
            String ip = "10.0.0." + (10 + i);
            int logins = 3 + rnd.nextInt(4);
            for (int j = 0; j < logins; j++) {
                boolean ok = rnd.nextInt(10) >= 1;
                events.add(new LogEvent(
                        day.atTime(9 + rnd.nextInt(9), rnd.nextInt(60), rnd.nextInt(60)),
                        ip, users[i], ok));
            }
        }

        // 2) ATTACK: brute force. One outside IP hammers admin/root at 2 AM.
        String attacker = "203.0.113.45";
        int second = 0;
        for (int i = 0; i < 20; i++) {
            second += 1 + rnd.nextInt(2);
            String target = (i % 3 == 0) ? "root" : "admin";
            events.add(new LogEvent(day.atTime(2, 14, 0).plusSeconds(second),
                    attacker, target, false));
        }

        // 3) ATTACK: odd-hour login. Priya normally works in the daytime.
        events.add(new LogEvent(day.atTime(3, 27, 45), "10.0.0.10", "priya", true));

        // 4) ATTACK: account spreading. Rahul logs in from 5 unfamiliar IPs
        //    within an hour, which suggests a stolen password.
        for (int i = 0; i < 5; i++) {
            events.add(new LogEvent(day.atTime(14, 5 * i, 10),
                    "198.51.100." + (20 + i), "rahul", true));
        }

        events.sort(Comparator.comparing(LogEvent::getTimestamp));

        try (PrintWriter out = new PrintWriter(new FileWriter(path))) {
            out.println("timestamp,ip,username,status");
            for (LogEvent e : events) {
                out.println(e.toCsv());
            }
        }
    }
}
