

python k8s_cluster_generator.py   --nodes 50   --use-case microservices   --seed 42   --generate-topology   --cve-json final.json   --vuln-db vulnerability_db.yml   -o out4/cluster.json;
python visualize_topology.py out4/cluster.json
python physical_node_generator.py \
    --input out4/cluster.json \
    --output out4/dev_cluster.json \
    --num-zones 1 \
    --firewall-probability 0.0 \
     --nodes 4 \
    --verbose

python visualize_physical_topology.py out4/dev_cluster.json 
python /home/ariel/Documents/thesis/CyberbattsimNetworkGenerators/cyberbattlesim_network_gen/network_generators/cloud/json_k8s_generator.py --config-file out4/dev_cluster.json  /content/drive/MyDrive/thesis/code/datasets/poc/generated/KubernetesCluster-v0
python test_on_cybersim.py