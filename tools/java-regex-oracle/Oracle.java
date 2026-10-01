import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runs every case in a cases file through java.util.regex and writes one JSON record per
 * (pattern, input, operation) to a JSON-lines file. Run through run.sh so the JDK is pinned.
 */
public final class Oracle {
    private static final String DEFAULT_REPLACEMENT = "<$0>";

    private final StringBuilder out = new StringBuilder();

    public static void main(String[] args) throws IOException {
        if (args.length != 2) {
            System.err.println("usage: Oracle <cases.json> <out.jsonl>");
            System.exit(2);
        }
        String text = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
        Object parsed = new Json(text).parse();
        Oracle oracle = new Oracle();
        for (Object group : (List<?>) parsed) {
            oracle.runGroup((Map<?, ?>) group);
        }
        Files.writeString(Path.of(args[1]), oracle.out.toString(), StandardCharsets.UTF_8);
        System.err.println("java " + System.getProperty("java.version") + ": wrote " + args[1]);
    }

    private void runGroup(Map<?, ?> group) {
        String pattern = (String) group.get("pattern");
        List<?> inputs = (List<?>) group.get("inputs");
        List<?> replacements = group.containsKey("replacements")
                ? (List<?>) group.get("replacements") : List.of();
        List<?> limits = group.containsKey("limits") ? (List<?>) group.get("limits") : List.of();

        Pattern compiled;
        try {
            compiled = Pattern.compile(pattern);
        } catch (Throwable t) {
            record(pattern, "compile", null, null, error(t));
            return;
        }
        record(pattern, "compile", null, null, "{\"ok\":" + compiled.matcher("").groupCount() + "}");

        List<String> allReplacements = new ArrayList<>();
        allReplacements.add(DEFAULT_REPLACEMENT);
        for (Object r : replacements) {
            allReplacements.add((String) r);
        }
        List<Long> allLimits = new ArrayList<>(List.of(0L));
        for (Object l : limits) {
            allLimits.add((Long) l);
        }

        for (Object rawInput : inputs) {
            String input = (String) rawInput;
            record(pattern, "matches", input, null, String.valueOf(compiled.matcher(input).matches()));
            record(pattern, "find", input, null, find(compiled, input));
            record(pattern, "find_all", input, null, findAll(compiled, input));
            for (String replacement : allReplacements) {
                record(pattern, "replace_all", input, str(replacement),
                        replace(() -> compiled.matcher(input).replaceAll(replacement)));
                record(pattern, "replace_first", input, str(replacement),
                        replace(() -> compiled.matcher(input).replaceFirst(replacement)));
            }
            for (Long limit : allLimits) {
                record(pattern, "split", input, String.valueOf(limit),
                        splitResult(compiled.split(input, limit.intValue())));
            }
        }
    }

    private static String find(Pattern pattern, String input) {
        Matcher m = pattern.matcher(input);
        if (!m.find()) {
            return "null";
        }
        StringBuilder sb = new StringBuilder();
        sb.append("{\"start\":").append(m.start()).append(",\"end\":").append(m.end()).append(",\"groups\":[");
        for (int g = 0; g <= m.groupCount(); g++) {
            if (g > 0) {
                sb.append(',');
            }
            String value = m.group(g);
            sb.append(value == null ? "null" : str(value));
        }
        return sb.append("]}").toString();
    }

    private static String findAll(Pattern pattern, String input) {
        Matcher m = pattern.matcher(input);
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        while (m.find()) {
            if (!first) {
                sb.append(',');
            }
            first = false;
            sb.append('[').append(m.start()).append(',').append(m.end()).append(']');
        }
        return sb.append(']').toString();
    }

    private interface Replace {
        String run();
    }

    private static String replace(Replace op) {
        try {
            return str(op.run());
        } catch (Throwable t) {
            return error(t);
        }
    }

    private static String splitResult(String[] parts) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append(str(parts[i]));
        }
        return sb.append(']').toString();
    }

    private static String error(Throwable t) {
        return "{\"error\":" + str(t.getClass().getSimpleName()) + "}";
    }

    /** Writes one record; {@code arg} is already JSON-encoded when present. */
    private void record(String pattern, String op, String input, String arg, String expected) {
        out.append("{\"pattern\":").append(str(pattern)).append(",\"op\":").append(str(op));
        if (input != null) {
            out.append(",\"input\":").append(str(input));
        }
        if (arg != null) {
            out.append(",\"arg\":").append(arg);
        }
        out.append(",\"expected\":").append(expected).append("}\n");
    }

    /** Encodes a string as ASCII-only JSON so that every code unit survives the round trip. */
    private static String str(String s) {
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"' -> sb.append("\\\"");
                case '\\' -> sb.append("\\\\");
                default -> {
                    if (c < 0x20 || c > 0x7e) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
                }
            }
        }
        return sb.append('"').toString();
    }

    /** Minimal JSON reader: objects, arrays, strings, integers, booleans, null. */
    private static final class Json {
        private final String src;
        private int pos;

        Json(String src) {
            this.src = src;
        }

        Object parse() {
            Object value = value();
            skipWs();
            if (pos != src.length()) {
                throw new IllegalStateException("trailing data at " + pos);
            }
            return value;
        }

        private void skipWs() {
            while (pos < src.length() && Character.isWhitespace(src.charAt(pos))) {
                pos++;
            }
        }

        private Object value() {
            skipWs();
            char c = src.charAt(pos);
            if (c == '{') {
                return object();
            } else if (c == '[') {
                return array();
            } else if (c == '"') {
                return string();
            } else if (src.startsWith("true", pos)) {
                pos += 4;
                return Boolean.TRUE;
            } else if (src.startsWith("false", pos)) {
                pos += 5;
                return Boolean.FALSE;
            } else if (src.startsWith("null", pos)) {
                pos += 4;
                return null;
            }
            int start = pos;
            while (pos < src.length() && "-0123456789".indexOf(src.charAt(pos)) >= 0) {
                pos++;
            }
            return Long.parseLong(src.substring(start, pos));
        }

        private Map<String, Object> object() {
            Map<String, Object> map = new LinkedHashMap<>();
            pos++;
            skipWs();
            if (src.charAt(pos) == '}') {
                pos++;
                return map;
            }
            while (true) {
                skipWs();
                String key = string();
                skipWs();
                expect(':');
                map.put(key, value());
                skipWs();
                if (src.charAt(pos) == ',') {
                    pos++;
                } else {
                    expect('}');
                    return map;
                }
            }
        }

        private List<Object> array() {
            List<Object> list = new ArrayList<>();
            pos++;
            skipWs();
            if (src.charAt(pos) == ']') {
                pos++;
                return list;
            }
            while (true) {
                list.add(value());
                skipWs();
                if (src.charAt(pos) == ',') {
                    pos++;
                } else {
                    expect(']');
                    return list;
                }
            }
        }

        private String string() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (true) {
                char c = src.charAt(pos++);
                if (c == '"') {
                    return sb.toString();
                }
                if (c != '\\') {
                    sb.append(c);
                    continue;
                }
                char e = src.charAt(pos++);
                switch (e) {
                    case 'n' -> sb.append('\n');
                    case 't' -> sb.append('\t');
                    case 'r' -> sb.append('\r');
                    case 'b' -> sb.append('\b');
                    case 'f' -> sb.append('\f');
                    case '/' -> sb.append('/');
                    case '\\' -> sb.append('\\');
                    case '"' -> sb.append('"');
                    case 'u' -> {
                        sb.append((char) Integer.parseInt(src.substring(pos, pos + 4), 16));
                        pos += 4;
                    }
                    default -> throw new IllegalStateException("bad escape \\" + e);
                }
            }
        }

        private void expect(char c) {
            if (src.charAt(pos) != c) {
                throw new IllegalStateException("expected " + c + " at " + pos);
            }
            pos++;
        }
    }
}
