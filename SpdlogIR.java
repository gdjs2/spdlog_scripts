import java.io.FileWriter;
import java.io.IOException;
import java.io.Writer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;

public class SpdlogIR extends GhidraScript {

    private Map<String, List<String>> getIRMap() {
        Map<String, List<String>> irMap = new HashMap<>();
        
        FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
        for (Function f: iter) {
            ArrayList<String> irList = new ArrayList<>();
            InstructionIterator instIter = currentProgram.getListing().getInstructions(f.getBody(), true);
            for (Instruction inst: instIter) 
                for (var pcodeOp: inst.getPcode()) 
                    irList.add(pcodeOp.toString());
            irMap.put(f.getName(), irList);
        }
        return irMap;
    }

    @Override
    public void run() {
        Map<String, List<String>> irMap = getIRMap();

        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        
        try (Writer writer = new FileWriter("/Users/gdjs2/Desktop/spdlog_graph.nosync/spdlog_scripts/irs.json")) {
            gson.toJson(irMap, writer);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }   
}
