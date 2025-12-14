from typing import Dict, List, Set, Tuple, Optional

class NodeZone:
    """Dynamic zone representation that supports unlimited zones"""
    
    @staticmethod
    def get_zones(count: int) -> List[str]:
        """Generate zone names for the specified count"""
        if count <= 0:
            return ["zone-a"]
        
        if count <= 26:
            return [f"zone-{chr(65 + i)}".lower() for i in range(count)]
        else:
            return [f"zone-{i+1}" for i in range(count)]

