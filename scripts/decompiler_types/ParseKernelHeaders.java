// Development only: parse a preprocessed DDK header using the imported PE target ABI.
// Arguments: HEADER OUTPUT.gdt. See README.md for preprocessing and export.
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.data.*;
public class ParseKernelHeaders extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        FileDataTypeManager m = CParserUtils.parseHeaderFiles(null, new String[]{a[0]}, null,
            new String[]{"-D__builtin_va_list=void *", "-D__extension__=", "-D__restrict=", "-D__restrict__="}, a[1],
            currentProgram.getLanguageID().toString(), "windows", monitor);
        m.close();
    }
}
