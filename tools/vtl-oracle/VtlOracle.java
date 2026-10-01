import com.jayway.jsonpath.Configuration;
import com.jayway.jsonpath.JsonPath;
import com.jayway.jsonpath.Option;
import com.jayway.jsonpath.spi.json.JsonSmartJsonProvider;
import com.jayway.jsonpath.spi.mapper.JsonSmartMappingProvider;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang.StringEscapeUtils;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;

/**
 * Renders mapping templates with Apache Velocity 1.7 and Jayway JsonPath, with $input, $util,
 * $context and $stageVariables stubbed after API Gateway's documented behavior.
 *
 * <p>Reads a JSON list of cases and writes one JSON object per case. Run through run.sh.
 */
public final class VtlOracle {
    private static final Configuration JSON_PATH = Configuration.builder()
            .jsonProvider(new JsonSmartJsonProvider())
            .mappingProvider(new JsonSmartMappingProvider())
            .options(Option.SUPPRESS_EXCEPTIONS)
            .build();

    private static final VelocityEngine ENGINE = newEngine();

    private static VelocityEngine newEngine() {
        VelocityEngine engine = new VelocityEngine();
        engine.setProperty(RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS,
                "org.apache.velocity.runtime.log.NullLogChute");
        engine.setProperty("directive.foreach.maxloops", "1000");
        engine.init();
        return engine;
    }

    public static void main(String[] args) throws IOException {
        if (args.length != 3) {
            System.err.println("usage: VtlOracle <defaults.json> <cases.json> <out.jsonl>");
            System.exit(2);
        }
        String defaults = Files.readString(Path.of(args[0]), StandardCharsets.UTF_8);
        String text = Files.readString(Path.of(args[1]), StandardCharsets.UTF_8);
        StringBuilder out = new StringBuilder();
        for (Object raw : (List<?>) new Json(text).parse()) {
            // Templates mutate $context, so every case starts from a fresh copy of the defaults.
            out.append(runCase((Map<?, ?>) raw, (Map<?, ?>) new Json(defaults).parse())).append('\n');
        }
        Files.writeString(Path.of(args[2]), out.toString(), StandardCharsets.UTF_8);
        System.err.println("velocity 1.7, java " + System.getProperty("java.version") + ": wrote " + args[2]);
    }

    /** The case's own value for a request field, else the shared default. */
    private static Object field(Map<?, ?> testCase, Map<?, ?> defaults, String key) {
        return testCase.containsKey(key) ? testCase.get(key) : defaults.get(key);
    }

    private static String runCase(Map<?, ?> testCase, Map<?, ?> defaults) {
        String name = (String) testCase.get("name");
        String template = (String) testCase.get("template");
        Map<String, Object> context = objectOrEmpty(field(testCase, defaults, "context"));
        Map<String, Object> stageVariables = objectOrEmpty(field(testCase, defaults, "stageVariables"));
        Map<String, Object> params = objectOrEmpty(field(testCase, defaults, "params"));
        String body = testCase.containsKey("body")
                ? (String) testCase.get("body")
                : Json.write(field(testCase, defaults, "bodyJson"));

        VelocityContext velocity = new VelocityContext();
        velocity.put("input", new Input(body, params));
        velocity.put("util", new Util());
        velocity.put("context", context);
        velocity.put("stageVariables", stageVariables);

        StringBuilder line = new StringBuilder("{\"name\":").append(Json.write(name));
        try {
            StringWriter writer = new StringWriter();
            ENGINE.evaluate(velocity, writer, "template", template);
            line.append(",\"output\":").append(Json.write(writer.toString()));
            line.append(",\"context\":").append(Json.write(velocity.get("context")));
        } catch (Throwable t) {
            line.append(",\"error\":").append(Json.write(t.getClass().getSimpleName()));
        }
        return line.append('}').toString();
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> objectOrEmpty(Object value) {
        return value == null ? new LinkedHashMap<>() : (Map<String, Object>) value;
    }

    /** Deep copy using plain ArrayList and LinkedHashMap, whose toString is Java's. */
    private static Object normalize(Object value) {
        if (value instanceof Map<?, ?> map) {
            Map<Object, Object> copy = new LinkedHashMap<>();
            for (Map.Entry<?, ?> e : map.entrySet()) {
                copy.put(e.getKey(), normalize(e.getValue()));
            }
            return copy;
        }
        if (value instanceof Collection<?> items) {
            List<Object> copy = new ArrayList<>();
            for (Object item : items) {
                copy.add(normalize(item));
            }
            return copy;
        }
        return value;
    }

    /** The $input object. */
    public static final class Input {
        private final String body;
        private final Map<String, Object> params;

        Input(String body, Map<String, Object> params) {
            this.body = body;
            this.params = params;
        }

        public String getBody() {
            return body;
        }

        public Object path(String path) {
            return normalize(JsonPath.using(JSON_PATH).parse(body).read(path));
        }

        public String json(String path) {
            return Json.writeCompact(path(path));
        }

        public Object params() {
            return params;
        }

        public String params(String name) {
            for (String where : new String[] {"path", "querystring", "header"}) {
                Object group = params.get(where);
                if (!(group instanceof Map<?, ?> map)) {
                    continue;
                }
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    String key = String.valueOf(e.getKey());
                    boolean same = where.equals("header") ? key.equalsIgnoreCase(name) : key.equals(name);
                    if (same && e.getValue() != null) {
                        return String.valueOf(e.getValue());
                    }
                }
            }
            return "";
        }
    }

    /** The $util object. */
    public static final class Util {
        public String escapeJavaScript(String text) {
            return StringEscapeUtils.escapeJavaScript(text);
        }

        public Object parseJson(String json) {
            return normalize(JSON_PATH.jsonProvider().parse(json));
        }

        public String urlEncode(String text) {
            return URLEncoder.encode(text, StandardCharsets.UTF_8);
        }

        public String urlDecode(String text) {
            return URLDecoder.decode(text, StandardCharsets.UTF_8);
        }

        public String base64Encode(String text) {
            return Base64.getEncoder().encodeToString(text.getBytes(StandardCharsets.UTF_8));
        }

        public String base64Decode(String text) {
            return new String(Base64.getDecoder().decode(text), StandardCharsets.UTF_8);
        }
    }

    /** Minimal JSON reader and writer; numbers follow json-smart's Integer, Long, Double typing. */
    private static final class Json {
        private final String src;
        private int pos;

        Json(String src) {
            this.src = src;
        }

        static String write(Object value) {
            StringBuilder sb = new StringBuilder();
            write(sb, value, true);
            return sb.toString();
        }

        /** Compact JSON with only the escapes JSON requires, like API Gateway's $input.json. */
        static String writeCompact(Object value) {
            StringBuilder sb = new StringBuilder();
            write(sb, value, false);
            return sb.toString();
        }

        private static void write(StringBuilder sb, Object value, boolean asciiOnly) {
            if (value == null) {
                sb.append("null");
            } else if (value instanceof Map<?, ?> map) {
                sb.append('{');
                boolean first = true;
                for (Map.Entry<?, ?> e : map.entrySet()) {
                    if (!first) {
                        sb.append(',');
                    }
                    first = false;
                    writeString(sb, String.valueOf(e.getKey()), asciiOnly);
                    sb.append(':');
                    write(sb, e.getValue(), asciiOnly);
                }
                sb.append('}');
            } else if (value instanceof Collection<?> items) {
                sb.append('[');
                boolean first = true;
                for (Object item : items) {
                    if (!first) {
                        sb.append(',');
                    }
                    first = false;
                    write(sb, item, asciiOnly);
                }
                sb.append(']');
            } else if (value instanceof String s) {
                writeString(sb, s, asciiOnly);
            } else if (value instanceof Number || value instanceof Boolean) {
                sb.append(value);
            } else {
                writeString(sb, value.toString(), asciiOnly);
            }
        }

        private static void writeString(StringBuilder sb, String s, boolean asciiOnly) {
            sb.append('"');
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                switch (c) {
                    case '"' -> sb.append("\\\"");
                    case '\\' -> sb.append("\\\\");
                    case '\n' -> sb.append("\\n");
                    case '\r' -> sb.append("\\r");
                    case '\t' -> sb.append("\\t");
                    case '\b' -> sb.append("\\b");
                    case '\f' -> sb.append("\\f");
                    default -> {
                        if (c < 0x20 || (asciiOnly && c > 0x7e)) {
                            sb.append(String.format("\\u%04x", (int) c));
                        } else {
                            sb.append(c);
                        }
                    }
                }
            }
            sb.append('"');
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
            return number();
        }

        private Object number() {
            int start = pos;
            while (pos < src.length() && "-+.eE0123456789".indexOf(src.charAt(pos)) >= 0) {
                pos++;
            }
            String text = src.substring(start, pos);
            if (text.contains(".") || text.contains("e") || text.contains("E")) {
                return Double.parseDouble(text);
            }
            long value = Long.parseLong(text);
            return (value >= Integer.MIN_VALUE && value <= Integer.MAX_VALUE) ? (Object) (int) value : (Object) value;
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
