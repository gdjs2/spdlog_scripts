import re
import pdb
import json
import torch
import gensim
import numpy as np

EMBBEDDING_DIM = 1 << 10
MODEL_FILE = 'doc2vec.model'
GRAPH_FILE_1 = 'callgraph.1.9.0.json'
GRAPH_FILE_2 = 'callgraph.1.12.0.json'
IR_FILE_1 = 'irs.1.9.0.json'
IR_FILE_2 = 'irs.1.12.0.json'

def load_model(filename):
    return gensim.models.Doc2Vec.load(filename)

def load_graph(filename):
    with open(filename) as f:
        d = json.load(f)
    
    nodes_cnt = len(d['nodes'])
    edges_cnt = len(d['edges'])
    nodes_list = d['nodes']

    adj_mat = torch.zeros((nodes_cnt, nodes_cnt))
    for edge in d['edges']:
        from_id = nodes_list.index(edge['from'])
        to_id = nodes_list.index(edge['to'])
        adj_mat[from_id, to_id] = 1

    return nodes_list, adj_mat

def load_irs(filename):
    with open(filename) as f:
        d = json.load(f)
    
    return d

def split_tokens(irs):
    pattern = r'\(.*?\)|[A-Z_]+|---'
    token_list = []
    for ir in irs:
        token_list += re.findall(pattern, ir)
    return token_list

def calculate_embeddings(nodes_list, irs_dic, model):
    nodes_cnt = len(nodes_list)
    emb_mat = torch.zeros((nodes_cnt, EMBBEDDING_DIM))

    for i in range(nodes_cnt):
        irs = irs_dic[nodes_list[i]]
        tokens = split_tokens(irs)
        emb_mat[i] = torch.tensor(model.infer_vector(tokens))

    return emb_mat


def calculate_similarity_matrix(emb_list1, emb_list2):
    # Convert to matrix multiplication
    emb_list1 = emb_list1
    emb_list2 = emb_list2.t()
    sim_mat = torch.mm(emb_list1, emb_list2)

    # Get modulus of each vector
    emb_list_norm1 = torch.norm(emb_list1, dim=1)
    emb_list_norm2 = torch.norm(emb_list2, dim=0)

    # Normalize
    sim_mat = sim_mat / torch.mm(emb_list_norm1.unsqueeze(1), emb_list_norm2.unsqueeze(0))

    return sim_mat

def main():
    # Prepare data
    model = load_model(MODEL_FILE)
    nodes_list1, adj_mat1 = load_graph(GRAPH_FILE_1)
    nodes_list2, adj_mat2 = load_graph(GRAPH_FILE_2)
    irs_dic1 = load_irs(IR_FILE_1)
    irs_dic2 = load_irs(IR_FILE_2)

    # Calculate embeddings
    emb_mat1 = calculate_embeddings(nodes_list1, irs_dic1, model)
    emb_mat2 = calculate_embeddings(nodes_list2, irs_dic2, model)

    sim_mat = calculate_similarity_matrix(emb_mat1, emb_mat2)

    package = (nodes_list1, nodes_list2, sim_mat)
    torch.save(package, 'sim_mat.pt')

    
if __name__ == '__main__':
    main()