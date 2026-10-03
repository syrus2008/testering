// ACET post-script: export the current program with the BinExport Ghidra extension (BinExport2 protobuf).
// Argument: output .BinExport path. Fails loudly if the extension is not installed.
//@category ACET
import ghidra.app.script.GhidraScript;
import ghidra.app.util.exporter.Exporter;
import java.io.File;

public class AcetBinExport extends GhidraScript {
    @Override
    public void run() throws Exception {
        String out = getScriptArgs()[0];
        Class<?> cls = Class.forName("com.google.security.binexport.BinExportExporter");
        Exporter exporter = (Exporter) cls.getDeclaredConstructor().newInstance();
        File tmp = new File(out + ".tmp");
        boolean ok = exporter.export(tmp, currentProgram, null, monitor);
        if (!ok || !tmp.isFile()) throw new RuntimeException("BinExport export failed");
        if (!tmp.renameTo(new File(out))) throw new RuntimeException("rename failed");
        println("ACET binexport complete: " + new File(out).length() + " bytes");
    }
}
