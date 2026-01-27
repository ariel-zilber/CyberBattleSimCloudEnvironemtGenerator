import random
from typing import List, Optional
from dataclasses import dataclass


@dataclass
class NetworkTopologyConfig:
    """Configuration for network topology between subnets"""

    topology_matrix: Optional[List[List[int]]] = None  # Adjacency matrix
    topology_type: str = "mesh"  # mesh, star, hub_spoke, random, exact
    connectivity_probability: float = 0.3  # For random topology

    def generate_topology(self, num_subnets: int) -> List[List[int]]:
        """Generate topology matrix based on configuration"""

        # 1. Handle Exact Topology explicitly
        if self.topology_type == "exact":
            if self.topology_matrix is None:
                raise ValueError(
                    "Topology type is 'exact' but no 'topology_matrix' was provided in the configuration."
                )

            # (Optional) We could validate len(matrix) == num_subnets here,
            # but usually the matrix defines the number of subnets, not the other way around.
            # If there's a mismatch, the caller (SubnetConfig logic) might need adjustment,
            # but returning the matrix is the correct action here.
            return self.topology_matrix

        # 2. Legacy/Override check: If matrix exists, use it (unless type forces generation?)
        # Keeping this for backward compatibility if matrix is passed without type="exact"
        if self.topology_matrix:
            return self.topology_matrix

        # 3. Standard Generation Types
        if self.topology_type == "mesh":
            return [
                [1 if i != j else 0 for j in range(num_subnets)]
                for i in range(num_subnets)
            ]

        elif self.topology_type == "star":
            matrix = [[0] * num_subnets for _ in range(num_subnets)]
            for i in range(1, num_subnets):
                matrix[0][i] = matrix[i][0] = 1
            return matrix

        elif self.topology_type == "hub_spoke":
            matrix = [[0] * num_subnets for _ in range(num_subnets)]
            for i in range(1, num_subnets):
                # Connect to Hub (0)
                matrix[0][i] = matrix[i][0] = 1
                # Random connection to another spoke
                if random.random() < 0.2:
                    j = random.randint(1, num_subnets - 1)
                    if i != j:
                        matrix[i][j] = matrix[j][i] = 1
            return matrix

        elif self.topology_type == "random":
            matrix = [[0] * num_subnets for _ in range(num_subnets)]
            for i in range(num_subnets):
                for j in range(i + 1, num_subnets):
                    if random.random() < self.connectivity_probability:
                        matrix[i][j] = matrix[j][i] = 1
            return matrix

        else:
            raise ValueError(f"Unknown topology type: {self.topology_type}")
