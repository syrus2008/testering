// ACET post-script: export a normalized function view as JSON (protocol: acet-ghidra-export@1).
// Argument: output JSON path. Read-only over the program; nothing is executed.
//@category ACET
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.block.*;
import ghidra.program.model.data.*;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.*;
import ghidra.program.model.util.CodeUnitInsertionException;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class AcetExport extends GhidraScript {
    private static String esc(String s) {
        if (s == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': b.append("\\\""); break;
                case '\\': b.append("\\\\"); break;
                case '\n': b.append("\\n"); break;
                case '\r': b.append("\\r"); break;
                case '\t': b.append("\\t"); break;
                default:
                    if (c < 0x20) b.append(String.format("\\u%04x", (int) c));
                    else b.append(c);
            }
        }
        return b.append('"').toString();
    }

    private String opClass(Instruction ins, int i) {
        int t = ins.getOperandType(i);
        if (OperandType.isRegister(t)) return "REG";
        if (OperandType.isDynamic(t)) return "MEM";
        if (OperandType.isAddress(t) || OperandType.isCodeReference(t)) return "ADDR";
        if (OperandType.isDataReference(t)) return "MEM";
        if (OperandType.isScalar(t)) return "IMM";
        return "OTHER";
    }

    @Override
    public void run() throws Exception {
        String out = getScriptArgs()[0];
        Program p = currentProgram;
        Listing listing = p.getListing();
        ReferenceManager refs = p.getReferenceManager();
        BasicBlockModel bbm = new BasicBlockModel(p);
        int errorBookmarks = p.getBookmarkManager().getBookmarkCount(BookmarkType.ERROR);
        StringBuilder sb = new StringBuilder(1 << 20);
        sb.append("{\"format\":\"acet-ghidra-export@1\",\"program\":{");
        sb.append("\"name\":").append(esc(p.getName()));
        sb.append(",\"language\":").append(esc(p.getLanguageID().toString()));
        sb.append(",\"compiler\":").append(esc(p.getCompilerSpec().getCompilerSpecID().toString()));
        sb.append(",\"image_base\":").append(p.getImageBase().getOffset());
        sb.append(",\"executable_format\":").append(esc(p.getExecutableFormat()));
        sb.append(",\"executable_sha256\":").append(esc(p.getExecutableSHA256()));
        sb.append(",\"error_bookmarks\":").append(errorBookmarks);
        sb.append(",\"blocks\":[");
        boolean firstB = true;
        for (MemoryBlock mb : p.getMemory().getBlocks()) {
            if (!firstB) sb.append(',');
            firstB = false;
            sb.append("{\"name\":").append(esc(mb.getName())).append(",\"start\":").append(mb.getStart().getOffset())
              .append(",\"size\":").append(mb.getSize()).append(",\"execute\":").append(mb.isExecute())
              .append(",\"initialized\":").append(mb.isInitialized()).append('}');
        }
        sb.append("]},\"functions\":[");
        int count = 0, insCount = 0;
        boolean firstF = true;
        for (Function f : listing.getFunctions(true)) {
            if (monitor.isCancelled()) break;
            if (f.isExternal()) continue;
            count++;
            if (!firstF) sb.append(',');
            firstF = false;
            AddressSetView body = f.getBody();
            MemoryBlock mb = p.getMemory().getBlock(f.getEntryPoint());
            sb.append("{\"entry\":").append(f.getEntryPoint().getOffset());
            sb.append(",\"name\":").append(esc(f.getName()));
            sb.append(",\"name_source\":").append(esc(f.getSymbol().getSource().toString()));
            sb.append(",\"size\":").append(body.getNumAddresses());
            sb.append(",\"thunk\":").append(f.isThunk());
            sb.append(",\"section\":").append(esc(mb == null ? null : mb.getName()));
            // basic blocks + intra-function successors
            sb.append(",\"blocks\":[");
            CodeBlockIterator it = bbm.getCodeBlocksContaining(body, monitor);
            boolean firstBlk = true;
            while (it.hasNext()) {
                CodeBlock cb = it.next();
                if (!firstBlk) sb.append(',');
                firstBlk = false;
                sb.append("{\"start\":").append(cb.getFirstStartAddress().getOffset())
                  .append(",\"size\":").append(cb.getNumAddresses()).append(",\"succ\":[");
                CodeBlockReferenceIterator dit = cb.getDestinations(monitor);
                boolean firstS = true;
                while (dit.hasNext()) {
                    CodeBlockReference r = dit.next();
                    Address d = r.getDestinationAddress();
                    if (!body.contains(d)) continue;
                    if (!firstS) sb.append(',');
                    firstS = false;
                    sb.append(d.getOffset());
                }
                sb.append("]}");
            }
            sb.append(']');
            // instructions: mnemonic + operand classes; scalars, strings and calls collected
            StringBuilder ins = new StringBuilder();
            TreeSet<Long> calls = new TreeSet<>();
            TreeSet<String> imports = new TreeSet<>();
            List<String> strings = new ArrayList<>();
            List<Long> consts = new ArrayList<>();
            boolean firstI = true;
            for (Instruction in : listing.getInstructions(body, true)) {
                insCount++;
                if (!firstI) ins.append(',');
                firstI = false;
                StringBuilder ops = new StringBuilder();
                for (int i = 0; i < in.getNumOperands(); i++) {
                    if (i > 0) ops.append(' ');
                    ops.append(opClass(in, i));
                    Scalar s = in.getScalar(i);
                    if (s != null && !OperandType.isAddress(in.getOperandType(i))) {
                        long v = s.getUnsignedValue();
                        if (v > 0xFF && consts.size() < 256) consts.add(v);
                    }
                }
                ins.append('[').append(esc(in.getMnemonicString())).append(',').append(esc(ops.toString())).append(']');
                for (Reference r : refs.getReferencesFrom(in.getAddress())) {
                    Address to = r.getToAddress();
                    if (r.getReferenceType().isCall()) {
                        Function cf = getFunctionAt(to);
                        if (cf != null && cf.isThunk()) cf = cf.getThunkedFunction(true);
                        if (cf != null && cf.isExternal()) imports.add(cf.getName());
                        else if (cf != null) calls.add(cf.getEntryPoint().getOffset());
                    } else if (r.getReferenceType().isData()) {
                        Data d = listing.getDataAt(to);
                        if (d != null && d.hasStringValue() && strings.size() < 128) {
                            Object v = d.getValue();
                            if (v != null) strings.add(v.toString());
                        } else if (to.isExternalAddress()) {
                            Symbol sym = p.getSymbolTable().getPrimarySymbol(to);
                            if (sym != null) imports.add(sym.getName());
                        }
                    }
                }
            }
            sb.append(",\"insns\":[").append(ins).append(']');
            sb.append(",\"calls\":[");
            boolean fc = true;
            for (Long c : calls) { if (!fc) sb.append(','); fc = false; sb.append(c); }
            sb.append("],\"imports\":[");
            fc = true;
            for (String s : imports) { if (!fc) sb.append(','); fc = false; sb.append(esc(s)); }
            sb.append("],\"strings\":[");
            fc = true;
            for (String s : strings) { if (!fc) sb.append(','); fc = false; sb.append(esc(s)); }
            sb.append("],\"constants\":[");
            fc = true;
            for (Long c : consts) { if (!fc) sb.append(','); fc = false; sb.append(c); }
            sb.append("]}");
        }
        sb.append("],\"counts\":{\"functions\":").append(count).append(",\"instructions\":").append(insCount)
          .append("},\"status\":\"complete\"}");
        File tmp = new File(out + ".tmp");
        try (Writer w = new OutputStreamWriter(new FileOutputStream(tmp), StandardCharsets.UTF_8)) {
            w.write(sb.toString());
        }
        if (!tmp.renameTo(new File(out))) throw new IOException("rename failed for " + out);
        println("ACET export complete: functions=" + count + " instructions=" + insCount);
    }
}
