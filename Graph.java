import java.io.Writer;
import java.util.ArrayList;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

public class Graph {
    private ArrayList<String> nodes;
    private ArrayList<Edge> edges;
    
    public Graph() {
        this.nodes = new ArrayList<String>();
        this.edges = new ArrayList<Edge>();
    }

    public void addNode(String node) {
        this.nodes.add(node);
    }

    public void addEdge(Edge edge) {
        this.edges.add(edge);
    }

    public void addEdge(String from, String to) {
        this.edges.add(new Edge(from, to));
    }

    public ArrayList<String> getNodes() {
        return this.nodes;
    }

    public ArrayList<Edge> getEdges() {
        return this.edges;
    }

    public void export(Writer writer) {
        Gson gson = new GsonBuilder().setPrettyPrinting().create();
        try {
            gson.toJson(this, writer);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
