// ACET pre-script: apply the analyzer selection of the Analysis Profile (ACET-GHD-004).
// Argument: path to a JSON object {"Analyzer Name": true|false, ...}
//@category ACET
import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import java.util.regex.*;

public class AcetSetAnalyzers extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) return;
        String json = new String(Files.readAllBytes(Paths.get(args[0])), "UTF-8");
        Matcher m = Pattern.compile("\"((?:[^\"\\\\]|\\\\.)*)\"\\s*:\\s*(true|false)").matcher(json);
        while (m.find()) {
            String name = m.group(1);
            boolean value = Boolean.parseBoolean(m.group(2));
            try {
                setAnalysisOption(currentProgram, name, Boolean.toString(value));
                println("ACET analyzer " + name + "=" + value);
            } catch (Exception e) {
                println("WARNING ACET analyzer option not found: " + name);
            }
        }
    }
}
