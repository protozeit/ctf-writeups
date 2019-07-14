import networkx as nx
import string

def find_all_paths(graph, start, end): 
    path  = [] 
    paths = [] 
    queue = [(start, end, path)] 
    while queue: 
        start, end, path = queue.pop() 
        print('Looking...', ''.join(path))

        path = path + [start] 
        if start == end: 
            paths.append(''.join(path)) 
        for node in set(graph[start]).difference(''.join(path)): 
            queue.append((node, end, path)) 
    return paths 


G = nx.Graph()
nodes = string.ascii_uppercase + string.digits + "_"
edges = {
    'A':['C','T'],
    'C':['A','7'],
    'D':['T','0'],
    'E':['Q','M'],
    'G':['O','_'],
    'K':['5','1'],
    'M':['E','5'],
    'N':['8','Q'],
    'O':['G','0'],
    'Q':['N','E'],
    'S':['_','4'],
    'T':['D','A','_','1'],
    'W':['_','4'],
    '0':['O','D'],
    '1':['T','K','7'],
    '4':['W','S'],
    '5':['M','K'],
    '7':['1','C'],
    '8':['N'],
    '_':['G','S','T','W'],
}

for n in nodes: G.add_node(n)
for k, v in edges.items():
	for c in v:
		G.add_edge(k,c)


print("Start candidates---------------------")
for n in nodes:
	for path in find_all_paths(G,n,'_'):
		print(''.join(path))
print("Finish candidates---------------------")
for n in nodes:
	for path in find_all_paths(G,'_',n):
		print(''.join(path))
print("Middle candidates---------------------")
for path in find_all_paths(G,'_','_'):
	print(''.join(path))

# print("Simple cycles")
# for cycle in nx.simple_cycles(G.to_directed()):
#  	print(cycle)

# print("find_all_paths------------------------")

# for n in nodes:
# 	for path in find_all_paths(G,'1','8'):
#		if '_' not in path:
#			print(''.join(path)) 
