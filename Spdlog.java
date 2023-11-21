import java.io.FileWriter;
import java.io.Writer;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;

public class Spdlog extends GhidraScript {
    private Graph createCallGraph() {
        Graph graph = new Graph();

        println("Constructing Function Call Graph...");

        FunctionManager fm = currentProgram.getFunctionManager();
        for (Function f: fm.getFunctions(true)) {
            graph.addNode(f.getName());
            for (Function callee: f.getCalledFunctions(monitor)) {
                graph.addEdge(new Edge(f.getName(), callee.getName()));
            }
        }

        println("Constructing Function Call Graph Done.");
        println(String.format("%d nodes, %d edges", graph.getNodes().size(), graph.getEdges().size()));

        return graph;

    }

    @Override
    public void run() throws Exception {
        
        Graph graph = createCallGraph();
        Writer writer = new FileWriter("/Users/gdjs2/Desktop/spdlog_graph.nosync/spdlog_scripts/callgraph.json");
        graph.export(writer);
        writer.close();

    }
}