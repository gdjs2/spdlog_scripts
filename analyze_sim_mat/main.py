# This file is used for analyze the similarity matrix (sim_mat.pt)
# sim_mat.pt contains a tuple of 3 elements:
#   1. nodes_list1
#   2. nodes_list2
#   3. sim_mat

import torch

def main():
    nodes_list1, nodes_list2, sim_mat = torch.load('binary_file/sim_mat.pt')
    len1 = len(nodes_list1)
    len2 = len(nodes_list2)

    for i in range(len1):
        for j in range(len2):
            if sim_mat[i][j] > 0.95:
                print(nodes_list1[i], nodes_list2[j], sim_mat[i][j])

if __name__ == '__main__':
    main()