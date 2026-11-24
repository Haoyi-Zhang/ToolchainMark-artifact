import antlr.Token;
import antlr.collections.AST;
import antlr.collections.impl.BitSet;
import java.io.InputStreamReader;
import java.io.Reader;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Comparator;

/** Observe generated code without changing its lexer or parser sources. */
public class LexerProbe {
    private static String hex(byte[] bytes) {
        StringBuilder out = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            out.append(Character.forDigit((b >>> 4) & 15, 16));
            out.append(Character.forDigit(b & 15, 16));
        }
        return out.toString();
    }

    private static String text(String value) {
        return value == null ? "NULL" : hex(value.getBytes(StandardCharsets.UTF_8));
    }

    private static void sets() throws Exception {
        Field[] fields = JavaLexer.class.getFields();
        Arrays.sort(fields, Comparator.comparing(Field::getName));
        for (Field field : fields) {
            if (!field.getName().startsWith("_tokenSet_")) continue;
            BitSet set = (BitSet) field.get(null);
            byte[] mask = new byte[8192];
            for (int value = 0; value < 65536; value++) {
                if (set.member(value)) mask[value >>> 3] |= (byte) (1 << (value & 7));
            }
            System.out.println("SET\t" + field.getName() + "\t" + hex(mask));
        }
    }

    public static void main(String[] args) {
        try {
            if (args.length == 1 && args[0].equals("sets")) {
                sets();
                return;
            }
            if (args.length != 2) throw new IllegalArgumentException("mode and input required");
            try (Reader reader = new InputStreamReader(Files.newInputStream(Paths.get(args[1])), StandardCharsets.UTF_8)) {
                JavaLexer lexer = new JavaLexer(reader);
                lexer.setFilename("input");
                if (args[0].equals("tokens")) {
                    for (int index = 0; index < 100000; index++) {
                        Token token = lexer.nextToken();
                        System.out.println("TOKEN\t" + token.getType() + "\t" + token.getLine() + "\t" + token.getColumn() + "\t" + text(token.getText()));
                        if (token.getType() == Token.EOF_TYPE) return;
                    }
                    throw new IllegalStateException("token limit reached");
                }
                if (!args[0].equals("parse")) throw new IllegalArgumentException("unknown mode");
                JavaRecognizer parser = new JavaRecognizer(lexer);
                parser.setFilename("input");
                parser.compilationUnit();
                AST ast = parser.getAST();
                System.out.println("PARSE_RETURNED\t" + text(ast == null ? null : ast.toStringList()));
            }
        } catch (Exception error) {
            System.out.println("EXCEPTION\t" + error.getClass().getName() + "\t" + text(error.getMessage()));
            System.exit(2);
        }
    }
}
