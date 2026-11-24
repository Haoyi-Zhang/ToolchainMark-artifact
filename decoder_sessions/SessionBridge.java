import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.*;

/** Acquires sequential public-API returns; contains no watermark judgments. */
public final class SessionBridge {
    private static String quote(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (int i=0; i<s.length(); i++) {
            char c=s.charAt(i);
            if (c=='\\' || c=='\"') b.append('\\').append(c);
            else if (c<32 || c>126) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    private static String json(Object value) {
        if (value==null) return "null";
        if (value instanceof String) return quote((String)value);
        if (value instanceof Boolean || value instanceof Number) return value.toString();
        StringBuilder b=new StringBuilder();
        if (value instanceof Map) {
            b.append('{'); boolean first=true;
            for (Object entryObject: ((Map<?,?>)value).entrySet()) {
                Map.Entry<?,?> e=(Map.Entry<?,?>)entryObject;
                if (!first) b.append(','); first=false;
                b.append(quote((String)e.getKey())).append(':').append(json(e.getValue()));
            }
            return b.append('}').toString();
        }
        if (value instanceof List) {
            b.append('['); boolean first=true;
            for (Object item: (List<?>)value) {
                if (!first) b.append(','); first=false; b.append(json(item));
            }
            return b.append(']').toString();
        }
        throw new IllegalArgumentException("Unsupported journal value");
    }
    private static void write(Path path, Object value) throws Exception {
        Path temp=path.resolveSibling(path.getFileName().toString()+".tmp");
        Files.write(temp, (json(value)+"\n").getBytes(StandardCharsets.UTF_8));
        Files.move(temp,path,StandardCopyOption.ATOMIC_MOVE);
    }
    private static Map<String,Object> properties(sandmark.util.ConfigProperties cp) {
        Map<String,Object> result=new TreeMap<>();
        if (cp==null) return result;
        for (Iterator it=cp.properties(); it.hasNext();) {
            String key=(String)it.next(); Object v=cp.getValue(key);
            Map<String,Object> item=new LinkedHashMap<>();
            item.put("java_type",v==null?null:v.getClass().getName());
            item.put("text",v==null?null:v.toString()); result.put(key,item);
        }
        return result;
    }
    private static String decode(String text) {
        return new String(Base64.getDecoder().decode(text),StandardCharsets.UTF_8);
    }
    public static void main(String[] args) throws Exception {
        if (args.length!=4) throw new IllegalArgumentException("Expected lifetime, algorithm class, journal directory, process token");
        String mode=args[0], className=args[1], token=args[3];
        if (!Arrays.asList("P","O","R").contains(mode)) throw new IllegalArgumentException("Unknown lifetime");
        Path journal=Paths.get(args[2]); Files.createDirectories(journal);
        sandmark.util.Random.getRandom().setSeed(0);
        Map<String,Object> ready=new LinkedHashMap<>();
        ready.put("kind","ready"); ready.put("process_token",token);
        ready.put("pid",ProcessHandle.current().pid()); ready.put("mode",mode);
        ready.put("algorithm_class",className); ready.put("startup_rng_seed",0);
        write(journal.resolve("ready.json"),ready);
        BufferedReader reader=new BufferedReader(new InputStreamReader(System.in,StandardCharsets.UTF_8));
        List<sandmark.watermark.StaticWatermarker> algorithms=new ArrayList<>();
        IdentityHashMap<sandmark.watermark.StaticWatermarker,Integer> algorithmIds=new IdentityHashMap<>();
        List<sandmark.program.Application> applications=new ArrayList<>();
        sandmark.watermark.StaticWatermarker previous=null, reused=null;
        int requestCount=0;
        for (String line; (line=reader.readLine())!=null;) {
            if (line.equals("STOP")) break;
            String[] fields=line.split("\t",-1);
            if (fields.length!=6) throw new IllegalArgumentException("Expected six base64 request fields");
            for (int i=0;i<fields.length;i++) fields[i]=decode(fields[i]);
            String request=fields[0], role=fields[1], target=fields[2], key=fields[3], original=fields[4], keyFile=fields[5];
            if (!request.matches("[a-z0-9-]+")) throw new IllegalArgumentException("Unsafe request identifier");
            if (mode.equals("P") && requestCount!=0) throw new IllegalStateException("Fresh-process arm received multiple requests");
            requestCount++;
            Map<String,Object> out=new LinkedHashMap<>();
            out.put("request_id",request); out.put("role",role); out.put("target",target);
            out.put("key",key); out.put("original_file",original); out.put("key_file",keyFile);
            out.put("process_token",token); out.put("pid",ProcessHandle.current().pid());
            out.put("mode",mode); out.put("algorithm_class",className); out.put("request_ordinal",requestCount);
            out.put("kind","request-start");
            write(journal.resolve(request+".start.json"),out);
            List<String> candidates=new ArrayList<>(), types=new ArrayList<>();
            boolean complete=false;
            try {
                sandmark.util.graph.graphview.GraphList.instance().clear();
                sandmark.watermark.StaticWatermarker alg;
                if (mode.equals("R") && reused!=null) alg=reused;
                else {
                    alg=(sandmark.watermark.StaticWatermarker)Class.forName(className).getDeclaredConstructor().newInstance();
                    algorithms.add(alg); algorithmIds.put(alg,algorithms.size()); if (mode.equals("R")) reused=alg;
                }
                out.put("algorithm_constructions",algorithms.size());
                out.put("algorithm_object_ordinal",algorithmIds.get(alg));
                out.put("same_algorithm_reference_as_previous",previous==null?null:alg==previous);
                previous=alg;
                if (className.equals("sandmark.watermark.dm.DM") || className.equals("sandmark.watermark.objectwm.ObjectWatermark"))
                    alg.getConfigProperties().setValue("Original File",new File(original));
                if (className.equals("sandmark.watermark.gtw.GTW"))
                    alg.getConfigProperties().setValue("Key File",new File(keyFile));
                sandmark.watermark.StaticWatermarker.getProperties().setValue("Key",key);
                sandmark.program.Application app=new sandmark.program.Application(target);
                out.put("same_application_reference_as_previous",applications.isEmpty()?null:app==applications.get(applications.size()-1));
                applications.add(app); out.put("application_constructions",applications.size());
                sandmark.watermark.StaticRecognizeParameters params=sandmark.watermark.StaticWatermarker.getRecognizeParams(app);
                out.put("parameter_key",params.key); out.put("parameter_application_is_current",params.app==app);
                out.put("properties_before",properties(alg.getConfigProperties()));
                out.put("graph_list_cleared",true);
                Iterator iterator=alg.recognize(params);
                if (iterator==null) {
                    out.put("kind","null-iterator");
                } else {
                    while (iterator.hasNext()) {
                        if (candidates.size()>=10000) throw new CandidateLimitException();
                        Object v=iterator.next(); candidates.add(v==null?null:v.toString());
                        types.add(v==null?null:v.getClass().getName());
                    }
                    complete=true; out.put("kind","extract-return");
                }
                out.put("properties_after",properties(alg.getConfigProperties()));
            } catch (Throwable problem) {
                problem.printStackTrace(System.err);
                out.put("kind",problem instanceof CandidateLimitException?"candidate-limit":"tool-exception");
                out.put("exception_class",problem.getClass().getName()); out.put("exception_message",problem.getMessage());
            }
            out.put("iteration_complete",complete); out.put("candidates",candidates); out.put("candidate_java_types",types);
            write(journal.resolve(request+".end.json"),out);
            if (!complete) break;
        }
        Map<String,Object> done=new LinkedHashMap<>();
        done.put("kind","process-complete"); done.put("process_token",token);
        done.put("requests_received",requestCount); done.put("algorithm_constructions",algorithms.size());
        done.put("application_constructions",applications.size());
        write(journal.resolve("done.json"),done);
    }
    private static final class CandidateLimitException extends RuntimeException {
        CandidateLimitException() { super("More than 10000 recognition candidates"); }
    }
}
