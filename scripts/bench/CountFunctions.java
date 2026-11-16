import ghidra.app.script.GhidraScript;
public class CountFunctions extends GhidraScript {
    @Override public void run() throws Exception {
        println("BENCH_FUNCTIONS=" + currentProgram.getFunctionManager().getFunctionCount());
    }
}
