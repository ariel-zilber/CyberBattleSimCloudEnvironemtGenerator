"""
Interactive Attack Path Solver with Flask Web UI

Reuses existing classes from cyberbattle and cyberbattlesim_cloud_gen.
Only requires: nodes: Dict[str, NodeInfo], attacker_node: str
"""

import ipaddress
import json
import time
from typing import Dict, List, Optional, Tuple, Any
from flask import Flask, jsonify, request, send_from_directory
from flask_cors import CORS

from cyberbattle.simulation.firewall import RulePermission
from cyberbattle.simulation.nodes import NodeInfo
from cyberbattle.simulation.vulenrabilites import (
    LateralMove,
    VulnerabilityInfo,
    VulnerabilityType,
)
from cyberbattlesim_cloud_gen.attack_path.attack_state import AttackState


class InteractiveAttackPathSolver:
    """
    Interactive attack path solver with Flask web UI.
    Reuses existing AttackState and NodeInfo classes.
    """
    
    def __init__(self, nodes: Dict[str, NodeInfo], attacker_node: str):
        self.nodes = nodes
        self.attacker_node = attacker_node
        self.non_target_nodes = {attacker_node}
        self.total_nodes = len(self.nodes) - len(self.non_target_nodes)
        
        # State management
        self.current_state: Optional[AttackState] = None
        self.history: List[Dict] = []
        self.step_count = 0
        self.start_time = time.time()
        
        self.reset()
    
    def reset(self):
        """Reset simulation to initial state"""
        self.current_state = AttackState.create_initial(self.attacker_node, self.nodes)
        self.history = []
        self.step_count = 0
        self.start_time = time.time()
    
    # ==================== Firewall Check (reused from AttackPathSolver) ====================
    
    def _check_firewall_access(self, source_node: str, target_node: str, port: str) -> bool:
        """Check if firewall rules allow access from source to target on given port"""
        if source_node not in self.nodes or target_node not in self.nodes:
            return False
        if source_node == target_node:
            return True
        
        source_info = self.nodes[source_node]
        target_info = self.nodes[target_node]
        source_ip = "0.0.0.0"
        if source_info.network_info and len(source_info.network_info) > 0:
            source_ip = source_info.network_info[0].ip_address
        
        target_ip = "0.0.0.0"
        if target_info.network_info and len(target_info.network_info) > 0:
            target_ip = target_info.network_info[0].ip_address
        
        # Check outgoing rules
        outgoing_allowed = False
        for rule in source_info.firewall.outgoing:
            if 'debug' in rule.reason:
                print(rule.permission,rule.port)
                x=1/0
            if rule.permission == RulePermission.ALLOW:
                if str(rule.subnet) in ["0.0.0.0/0", "*"]:
                    if str(rule.port) in ["*", str(port)]:
                        outgoing_allowed = True
                        break
                try:
                    rule_subnet = str(rule.subnet) if '/' in str(rule.subnet) else f"{rule.subnet}/32"
                    if (target_ip == "0.0.0.0" or 
                        ipaddress.ip_address(target_ip) in ipaddress.ip_network(rule_subnet, strict=False)):
                        if str(rule.port) in ["*", str(port)]:
                            outgoing_allowed = True
                            break
                except:
                    continue
        
        if not outgoing_allowed:
            return False
        
        # Check incoming rules
        incoming_allowed = False
        for rule in target_info.firewall.incoming:
            if rule.permission == RulePermission.ALLOW:
                if str(rule.subnet) in ["0.0.0.0/0", "*"]:
                    if str(rule.port) in ["*", str(port)]:
                        incoming_allowed = True
                        break
                try:
                    rule_subnet = str(rule.subnet) if '/' in str(rule.subnet) else f"{rule.subnet}/32"
                    if (source_ip == "0.0.0.0" or 
                        ipaddress.ip_address(source_ip) in ipaddress.ip_network(rule_subnet, strict=False)):
                        if str(rule.port) in ["*", str(port)]:
                            incoming_allowed = True
                            break
                except:
                    continue
        
        return outgoing_allowed and incoming_allowed
    
    # ==================== Actions (reused logic from AttackPathSolver) ====================
    
    def _get_available_actions(self) -> List[Tuple]:
        """Generate all possible actions from current state (same logic as AttackPathSolver)"""
        state = self.current_state
        attack_actions = []
        movement_actions = []
        print("state",state)
        if state.current_source in self.nodes:

            # Local exploits
            for v_name, v_info in self.nodes[state.current_source].vulnerabilities.items():
                if v_info.type == VulnerabilityType.LOCAL:
                    attack_actions.append((
                        "local_exploit",
                        state.current_source,
                        state.current_source,
                        v_name,
                        v_info,
                        None
                    ))
            
            # Remote exploits and connections
            if (state.current_source != state.current_destination and 
                state.current_destination in self.nodes):
                print('-----------------------')
                print("target",state.current_destination)
                
                target_info = self.nodes[state.current_destination]
                
                # Remote exploits
                for v_name, v_info in target_info.vulnerabilities.items():
                    print('vuln',v_name,v_info.type)
                    if v_info.type == VulnerabilityType.REMOTE:
                        if self._check_firewall_access(state.current_source, state.current_destination, "*"):
                            print('ok')
                            attack_actions.append((
                                "remote_exploit",
                                state.current_source,
                                state.current_destination,
                                v_name,
                                v_info,
                                None
                            ))
                        else:
                            print('not ok')
                
                # Service connections (only if not owned yet)
                if state.current_destination not in state.owned_nodes:
                    for service in target_info.services:
                        if self._check_firewall_access(state.current_source, state.current_destination, service.name):
                            allowed_creds = set(service.allowedCredentials) if service.allowedCredentials else set()
                            protocol = getattr(service, 'protocol', None)
                            if state.has_credential_for_service(
                                state.current_destination,
                                str(service.name),
                                service.name,
                                protocol,
                                allowed_creds
                            ):
                                connect_vuln = VulnerabilityInfo(
                                    f"Connect {service.name}",
                                    VulnerabilityType.REMOTE,
                                    LateralMove(),
                                    1.0,
                                    f"Connected {state.current_destination}"
                                )
                                attack_actions.append((
                                    "connect",
                                    state.current_source,
                                    state.current_destination,
                                    f"Connect_{service.name}",
                                    connect_vuln,
                                    service.name
                                ))
        
        # Movement actions
        for n in state.owned_nodes:
            if n != state.current_source:
                movement_actions.append((
                    "change_source",
                    state.current_source,
                    n,
                    f"Change source to {n}",
                    None,
                    None
                ))
        
        for n in state.known_nodes:
            if n != state.current_destination:
                movement_actions.append((
                    "change_destination",
                    state.current_destination,
                    n,
                    f"Change destination to {n}",
                    None,
                    None
                ))
        
        return attack_actions + movement_actions
    
    def _apply_action(self, action: Tuple) -> Tuple[AttackState, float]:
        """Apply action to state (same logic as AttackPathSolver)"""
        action_type, _, target_node, _, vuln_info, _ = action
        
        if action_type == "change_source":
            return self.current_state.apply_movement(new_source=target_node), 0.1
        elif action_type == "change_destination":
            return self.current_state.apply_movement(new_destination=target_node), 0.1
        elif vuln_info and vuln_info.outcome:
            cost = vuln_info.cost
            new_state = self.current_state.apply_outcome(target_node, vuln_info.outcome, self.nodes)
            return new_state, cost
        
        return self.current_state, 1.0
    
    # ==================== Public API ====================
    
    def get_available_actions(self) -> List[Dict]:
        """Get available actions as list of dicts for JSON"""
        actions = self._get_available_actions()
        result = []
        for i, action in enumerate(actions):
            print(action)
            action_type, source, target, name, vuln_info, service = action
            result.append({
                "action_id": f"action_{i}",
                "action_type": action_type,
                "source_node": source,
                "target_node": target,
                "vuln_name": name,
                "cost": vuln_info.cost if vuln_info else 0.1,
                "description": f"{action_type}: {name}" if vuln_info else name
            })
        return result
    
    def execute_action(self, action_id: str) -> Dict:
        """Execute action by ID and return result"""
        actions = self._get_available_actions()
        
        try:
            idx = int(action_id.replace("action_", ""))
            if idx < 0 or idx >= len(actions):
                return {"success": False, "message": f"Invalid action ID: {action_id}"}
        except:
            return {"success": False, "message": f"Invalid action ID format: {action_id}"}
        
        action = actions[idx]
        
        # Save state before
        state_before = self.current_state.to_dict()
        owned_before = self.current_state.get_owned_count(self.non_target_nodes)
        known_before = len(self.current_state.known_nodes)
        creds_before = len(self.current_state.credentials)
        
        # Apply action
        new_state, cost = self._apply_action(action)
        self.current_state = new_state
        
        # Calculate progress
        owned_after = self.current_state.get_owned_count(self.non_target_nodes)
        known_after = len(self.current_state.known_nodes)
        creds_after = len(self.current_state.credentials)
        
        progress = {
            "owned_delta": owned_after - owned_before,
            "known_delta": known_after - known_before,
            "creds_delta": creds_after - creds_before,
            "progress_made": (owned_after > owned_before or known_after > known_before or creds_after > creds_before)
        }
        
        # Record history
        self.step_count += 1
        self.history.append({
            "step": self.step_count,
            "action": {
                "action_type": action[0],
                "source_node": action[1],
                "target_node": action[2],
                "vuln_name": action[3],
                "cost": action[4].cost if action[4] else 0.1
            },
            "state_before": state_before,
            "progress_made": progress
        })
        
        return {
            "success": True,
            "message": f"Executed: {action[3]}",
            "progress": progress
        }
    
    def undo(self) -> Dict:
        """Undo last action"""
        if not self.history:
            return {"success": False, "message": "No actions to undo"}
        
        last = self.history.pop()
        self.step_count -= 1
        
        # Restore state
        prev = last["state_before"]
        self.current_state = AttackState(
            current_source=prev["current_source"],
            current_destination=prev["current_destination"],
            owned_nodes=frozenset(prev["owned_nodes"]),
            known_nodes=frozenset(prev["known_nodes"]),
            credentials=frozenset(tuple(c) if isinstance(c, list) else c for c in prev["credentials"])
        )
        
        return {"success": True, "message": f"Undone: {last['action']['vuln_name']}"}
    
    def get_status(self) -> Dict:
        """Get current status"""
        owned = self.current_state.get_owned_count(self.non_target_nodes)
        return {
            "step": self.step_count,
            "owned_nodes": owned,
            "total_target_nodes": self.total_nodes,
            "completion_percentage": (owned / self.total_nodes * 100) if self.total_nodes > 0 else 0,
            "known_nodes_count": len(self.current_state.known_nodes),
            "credentials_count": len(self.current_state.credentials),
            "current_source": self.current_state.current_source,
            "current_destination": self.current_state.current_destination
        }
    

    def export_state(self) -> Dict:
            """Export full state for web UI"""
            # Build nodes data
            nodes_data = []
            for node_id, node_info in self.nodes.items():
                # Handle properties - could be dict, list, or other type
                props = {}
                if hasattr(node_info, 'properties') and node_info.properties:
                    if isinstance(node_info.properties, dict):
                        props = node_info.properties
                    elif hasattr(node_info.properties, '__iter__'):
                        # It's iterable but not a dict - convert to list
                        props = {"values": list(node_info.properties)}
                    else:
                        props = {"value": str(node_info.properties)}
                
                nodes_data.append({
                    "id": node_id,
                    "is_attacker": node_id == self.attacker_node,
                    "ip_address": node_info.network_info[0].ip_address if node_info.network_info else "0.0.0.0",
                    "vulnerabilities": [
                        {"name": v_name, "type": v_info.type.name, "cost": v_info.cost}
                        for v_name, v_info in node_info.vulnerabilities.items()
                    ],
                    "services": [{"name": s.name} for s in node_info.services],
                    "properties": props
                })
            
            # Build edges
            edges = []
            edge_set = set()
            for node_id in self.nodes:
                for other_id in self.nodes:
                    if other_id != node_id:
                        key = tuple(sorted([node_id, other_id]))
                        if key not in edge_set and self._check_firewall_access(node_id, other_id, "*"):
                            edges.append({"source": node_id, "target": other_id})
                            edge_set.add(key)
            
            # --- FIX STARTS HERE ---
            # Explicitly handle the state dictionary to ensure sets are lists
            # We assume self.current_state exists
            current_state_dict = self.current_state.to_dict()
            
            # Force conversion of sets to lists for JSON serialization
            # This overrides whatever to_dict() returned if it wasn't a list
            current_state_dict['owned_nodes'] = list(self.current_state.owned_nodes)
            current_state_dict['known_nodes'] = list(self.current_state.known_nodes)
            # --- FIX ENDS HERE ---

            return {
                "metadata": {
                    "attacker_node": self.attacker_node,
                    "total_nodes": len(self.nodes),
                    "target_nodes": self.total_nodes
                },
                "nodes": nodes_data,
                "edges": edges,
                "current_state": current_state_dict, # Use the modified dict
                "status": self.get_status(),
                "available_actions": self.get_available_actions(),
                "history": self.history
            }

def create_flask_app(solver: InteractiveAttackPathSolver, html_path: str = None) -> Flask:
    """Create Flask app for the interactive solver"""
    app = Flask(__name__)
    CORS(app)
    
    @app.route('/')
    def index():
        if html_path:
            import os
            return send_from_directory(os.path.dirname(html_path), os.path.basename(html_path))
        return "Interactive Attack Path Solver API. Use /api/export to get state."
    
    @app.route('/api/export')
    def export():
        return jsonify(solver.export_state())
    
    @app.route('/api/status')
    def status():
        return jsonify(solver.get_status())
    
    @app.route('/api/actions')
    def actions():
        return jsonify(solver.get_available_actions())
    
    @app.route('/api/action/<action_id>', methods=['POST'])
    def execute(action_id):
        result = solver.execute_action(action_id)
        result["status"] = solver.get_status()
        result["available_actions"] = solver.get_available_actions()
        return jsonify(result)
    
    @app.route('/api/undo', methods=['POST'])
    def undo():
        result = solver.undo()
        result["status"] = solver.get_status()
        result["available_actions"] = solver.get_available_actions()
        return jsonify(result)
    
    @app.route('/api/reset', methods=['POST'])
    def reset():
        solver.reset()
        return jsonify({
            "success": True,
            "message": "Reset",
            "status": solver.get_status(),
            "available_actions": solver.get_available_actions()
        })
    
    return app


def run_interactive_server(nodes: Dict[str, NodeInfo], attacker_node: str, 
                           port: int = 5000, html_path: str = None):
    """
    Run interactive attack path solver with Flask web UI.
    
    Args:
        nodes: Dictionary of node ID to NodeInfo
        attacker_node: ID of the attacker's starting node
        port: Port to run server on (default 5000)
        html_path: Path to HTML file (optional, for serving UI)
    """
    solver = InteractiveAttackPathSolver(nodes, attacker_node)
    app = create_flask_app(solver, html_path)
    
    print(f"\n{'='*60}")
    print("INTERACTIVE ATTACK PATH SOLVER")
    print(f"{'='*60}")
    print(f"Attacker node: {attacker_node}")
    print(f"Total nodes: {len(nodes)}")
    print(f"Target nodes: {solver.total_nodes}")
    print(f"\nServer running at: http://localhost:{port}")
    print(f"API endpoints:")
    print(f"  GET  /api/export  - Get full state")
    print(f"  GET  /api/status  - Get current status")
    print(f"  GET  /api/actions - Get available actions")
    print(f"  POST /api/action/<id> - Execute action")
    print(f"  POST /api/undo    - Undo last action")
    print(f"  POST /api/reset   - Reset simulation")
    print(f"{'='*60}\n")
    
    app.run(host='0.0.0.0', port=port, debug=False)


# Example usage
if __name__ == "__main__":
    print("Usage:")
    print("  from interactive_attack_solver import run_interactive_server")
    print("  run_interactive_server(nodes, attacker_node, port=5000)")