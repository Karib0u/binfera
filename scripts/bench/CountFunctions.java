import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;

public class CountFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        int all = 0, thunks = 0;
        for (Function f : currentProgram.getFunctionManager().getFunctions(true)) {
            all++;
            if (f.isThunk()) thunks++;
        }
        println("BENCH_FUNCTIONS=" + all);
        println("BENCH_THUNKS=" + thunks);
        println("BENCH_NONTHUNK=" + (all - thunks));
    }
}
