import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;

/** Thin API bridge. It does not implement, repair, or judge a watermark. */
public final class SandmarkBridge {
    private static String quote(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' || c == '"') b.append('\\').append(c);
            else if (c < 32 || c > 126) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 10) throw new IllegalArgumentException("Expected ten bridge arguments");
        String operation = args[0], className = args[1], input = args[2];
        File output = new File(args[3]), result = new File(args[4]);
        String payload = args[5], key = args[6], original = args[7], keyFile = args[8];
        long seed = Long.parseLong(args[9]);
        String body;
        int code = 0;
        try {
            sandmark.util.Random.getRandom().setSeed(seed);
            sandmark.watermark.StaticWatermarker algorithm =
                (sandmark.watermark.StaticWatermarker)Class.forName(className).getDeclaredConstructor().newInstance();
            if (className.equals("sandmark.watermark.dm.DM") ||
                className.equals("sandmark.watermark.objectwm.ObjectWatermark"))
                algorithm.getConfigProperties().setValue("Original File", new File(original));
            if (className.equals("sandmark.watermark.gtw.GTW"))
                algorithm.getConfigProperties().setValue("Key File", new File(keyFile));
            sandmark.program.Application app = new sandmark.program.Application(input);
            sandmark.util.ConfigProperties cp = sandmark.watermark.StaticWatermarker.getProperties();
            cp.setValue("Key", key);
            if (operation.equals("embed")) {
                cp.setValue("Watermark", payload);
                algorithm.embed(sandmark.watermark.StaticWatermarker.getEmbedParams(app));
                app.save(output);
                body = "{\"kind\":\"embed-return\",\"algorithm\":" + quote(className) + "}";
            } else if (operation.equals("extract")) {
                Iterator iterator = algorithm.recognize(sandmark.watermark.StaticWatermarker.getRecognizeParams(app));
                ArrayList<String> candidates = new ArrayList<String>();
                ArrayList<String> types = new ArrayList<String>();
                while (iterator.hasNext()) {
                    if (candidates.size() >= 10000)
                        throw new IllegalStateException("Acquisition limit: more than 10000 extractor candidates");
                    Object value = iterator.next();
                    candidates.add(value == null ? null : value.toString());
                    types.add(value == null ? null : value.getClass().getName());
                }
                StringBuilder b = new StringBuilder("{\"kind\":\"extract-return\",\"candidates\":[");
                for (int i=0;i<candidates.size();i++) { if (i>0) b.append(','); b.append(quote(candidates.get(i))); }
                b.append("],\"candidate_java_types\":[");
                for (int i=0;i<types.size();i++) { if (i>0) b.append(','); b.append(quote(types.get(i))); }
                body = b.append("]}").toString();
            } else throw new IllegalArgumentException("Unknown bridge operation");
        } catch (Throwable problem) {
            problem.printStackTrace(System.err);
            body = "{\"kind\":\"tool-exception\",\"exception_class\":" + quote(problem.getClass().getName())
                + ",\"message\":" + quote(problem.getMessage()) + "}";
            code = 2;
        }
        try (PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(result), StandardCharsets.UTF_8))) {
            writer.println(body);
        }
        if (code != 0) System.exit(code);
    }
}
