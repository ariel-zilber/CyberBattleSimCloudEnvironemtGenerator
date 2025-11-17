

python k8s_cluster_generator_enhanced.py.py   --config /home/ariel/Documents/thesis/CyberBattleSimExperimentsConfigs/cloud_generators/example.yaml --cve-json final.json   --vuln-db vulnerability_db.yml   -o out6/cluster.json;
python visualize_topology.py out4/cluster.json





# python physical_node_generator.py --input out4/cluster.json --output out4/cluster_with_nodes_balanced.json -v --nodes 5 --zone-distribution balanced
# python physical_node_generator.py --input out4/cluster.json --output out4/cluster_with_nodes.json -v --nodes 5 --zone-distribution balanced
# python physical_node_generator.py \
#     --input out4/cluster.json \
#     --output out4/multiregion_cluster.json \
#     --num-zones 4 \
#     --zone-distribution unbalanced \
#     --firewall-probability 0.5 \
#     --firewall-cross-zone-only \
#      --nodes 10 \
#     --verbose
# python physical_node_generator.py \
#     --input out4/cluster.json \
#     --output out4/dr_cluster.json \
#     --num-zones 2 \
#     --zone-distribution primary-backup \
#      --nodes 10 \
#     --verbose
python physical_node_generator.py \
    --input out4/cluster.json \
    --output out4/dev_cluster.json \
    --num-zones 1 \
    --firewall-probability 0.0 \
     --nodes 4 \
    --verbose
# python physical_node_generator.py \
#     --input out4/cluster.json \
#     --output out4/secure_cluster.json \
#     --num-zones 10 \
#     --zone-distribution balanced \
#     --firewall-probability 0.8 \
#     --firewall-cross-zone-only \
#      --nodes 10 \
#     --verbose

# python visualize_physical_topology.py out4/cluster_with_nodes.json 
# python visualize_physical_topology.py out4/cluster_with_nodes_balanced.json 
# python visualize_physical_topology.py out4/multiregion_cluster.json 
# python visualize_physical_topology.py out4/dr_cluster.json 
python visualize_physical_topology.py out4/dev_cluster.json 
# python visualize_physical_topology.py out4/secure_cluster.json 
# python cyberbattlesim_generator.py --input out4/cluster.json --output out4/attack_scenario.json


python /home/ariel/Documents/thesis/CyberbattsimNetworkGenerators/cyberbattlesim_network_gen/network_generators/cloud/json_k8s_generator.py --config-file out4/dev_cluster.json  /content/drive/MyDrive/thesis/code/datasets/poc/generated/KubernetesCluster-v0
python test_on_cybersim.py