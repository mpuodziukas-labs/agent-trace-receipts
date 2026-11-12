package dev.puodziukas.receipts;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Minimal strict JSON reader (RFC 8259). Objects become Map, arrays List, integers Long. */
final class Json {
    private static final int MAX_DEPTH = 200;

    private final String s;
    private int pos;

    private Json(String s) {
        this.s = s;
    }

    /** Parses one JSON value that spans the whole input. Throws IllegalArgumentException if malformed. */
    static Object parse(String text) {
        Json j = new Json(text);
        j.ws();
        Object v = j.value(0);
        j.ws();
        if (j.pos != j.s.length()) {
            throw j.fail("trailing characters");
        }
        return v;
    }

    private IllegalArgumentException fail(String why) {
        return new IllegalArgumentException("JSON error at " + pos + ": " + why);
    }

    private void ws() {
        while (pos < s.length()) {
            char c = s.charAt(pos);
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                pos++;
            } else {
                break;
            }
        }
    }

    private char peek() {
        if (pos >= s.length()) {
            throw fail("unexpected end");
        }
        return s.charAt(pos);
    }

    private void expect(char c) {
        if (peek() != c) {
            throw fail("expected '" + c + "'");
        }
        pos++;
    }

    private Object value(int depth) {
        if (depth > MAX_DEPTH) {
            throw fail("nesting too deep");
        }
        char c = peek();
        switch (c) {
            case '{':
                return object(depth);
            case '[':
                return array(depth);
            case '"':
                return string();
            case 't':
                return literal("true", Boolean.TRUE);
            case 'f':
                return literal("false", Boolean.FALSE);
            case 'n':
                return literal("null", null);
            default:
                return number();
        }
    }

    private Object literal(String word, Object v) {
        if (!s.startsWith(word, pos)) {
            throw fail("bad literal");
        }
        pos += word.length();
        return v;
    }

    private Map<String, Object> object(int depth) {
        Map<String, Object> m = new LinkedHashMap<>();
        expect('{');
        ws();
        if (peek() == '}') {
            pos++;
            return m;
        }
        while (true) {
            ws();
            String k = string();
            ws();
            expect(':');
            ws();
            m.put(k, value(depth + 1));
            ws();
            if (peek() == ',') {
                pos++;
            } else {
                expect('}');
                return m;
            }
        }
    }

    private List<Object> array(int depth) {
        List<Object> l = new ArrayList<>();
        expect('[');
        ws();
        if (peek() == ']') {
            pos++;
            return l;
        }
        while (true) {
            ws();
            l.add(value(depth + 1));
            ws();
            if (peek() == ',') {
                pos++;
            } else {
                expect(']');
                return l;
            }
        }
    }

    private String string() {
        expect('"');
        StringBuilder b = new StringBuilder();
        while (true) {
            char c = peek();
            pos++;
            if (c == '"') {
                return b.toString();
            }
            if (c < 0x20) {
                throw fail("control character in string");
            }
            if (c != '\\') {
                b.append(c);
                continue;
            }
            char e = peek();
            pos++;
            switch (e) {
                case '"': b.append('"'); break;
                case '\\': b.append('\\'); break;
                case '/': b.append('/'); break;
                case 'b': b.append('\b'); break;
                case 'f': b.append('\f'); break;
                case 'n': b.append('\n'); break;
                case 'r': b.append('\r'); break;
                case 't': b.append('\t'); break;
                case 'u':
                    if (pos + 4 > s.length()) {
                        throw fail("short \\u escape");
                    }
                    try {
                        b.append((char) Integer.parseInt(s.substring(pos, pos + 4), 16));
                    } catch (NumberFormatException ex) {
                        throw fail("bad \\u escape");
                    }
                    pos += 4;
                    break;
                default:
                    throw fail("bad escape");
            }
        }
    }

    private Object number() {
        int start = pos;
        while (pos < s.length() && "+-0123456789.eE".indexOf(s.charAt(pos)) >= 0) {
            pos++;
        }
        String t = s.substring(start, pos);
        if (t.isEmpty()) {
            throw fail("unexpected character");
        }
        try {
            if (t.indexOf('.') < 0 && t.indexOf('e') < 0 && t.indexOf('E') < 0) {
                return Long.parseLong(t);
            }
            return Double.parseDouble(t);
        } catch (NumberFormatException ex) {
            throw fail("bad number");
        }
    }
}
