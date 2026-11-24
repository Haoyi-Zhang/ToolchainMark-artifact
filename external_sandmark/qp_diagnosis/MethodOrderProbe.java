import java.io.PrintWriter;
import java.io.File;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Iterator;

/** Post-hoc read-only probe of the original method traversal schedule. */
public final class MethodOrderProbe {
    public static void main(String[] args) throws Exception {
        sandmark.program.Application app = new sandmark.program.Application(args[0]);
        ArrayList<sandmark.program.Method> methods = new ArrayList<sandmark.program.Method>();
        for (Iterator classes = app.classes(); classes.hasNext();) {
            sandmark.program.Class clazz = (sandmark.program.Class)classes.next();
            if (clazz.isInterface() || clazz.isAbstract()) continue;
            for (Iterator items = clazz.methods(); items.hasNext();) {
                sandmark.program.Method method = (sandmark.program.Method)items.next();
                if (method.getInstructionList() != null) methods.add(method);
            }
        }
        Collections.sort(methods, new sandmark.watermark.assignlv.MethodCompare());
        long seed = sandmark.util.StringInt.encode(args[1]).longValue();
        java.util.Random random = new java.util.Random(seed);
        int left = methods.size();
        int ordinal = 0;
        try (PrintWriter out = new PrintWriter(new File(args[2]), "UTF-8")) {
            while (left != 0) {
                int slot = Math.abs(random.nextInt()) % methods.size();
                sandmark.program.Method method = methods.get(slot);
                if (method == null) continue;
                methods.set(slot, null);
                left--;
                out.println((ordinal++) + "\t" + method.getClassName() + "\t" + method.getName()
                    + "\t" + method.getSignature() + "\t" + method.getInstructionList().getLength()
                    + "\t" + method.getInstructionList().getStart().toString());
            }
        }
    }
}
