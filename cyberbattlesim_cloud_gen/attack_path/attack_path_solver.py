import ipaddress
import sys
import time
from typing import Dict,   Optional,   Tuple
from cyberbattle.simulation.firewall import   RulePermission
from cyberbattle.simulation.nodes import NodeInfo
from cyberbattle.simulation.vulenrabilites import (
    LateralMove,
    VulnerabilityInfo,
    VulnerabilityType,
)
from cyberbattlesim_cloud_gen.attack_path.exceptions import SearchStateLimitError,SearchTimeoutError
from cyberbattlesim_cloud_gen.attack_path.attack_state import AttackState
sys.setrecursionlimit(25000) 
IS_DEBUG=False
class AttackPathSolver:
    """
    Refactored attack_path using AttackState class for state management.
    Uses iterative DFS with prioritization to find optimal attack paths.
    Non-recursive implementation using explicit stack.
    """
    
    def __init__(self, nodes: Dict[str, NodeInfo], attacker_node: str):
        self.nodes = nodes
        self.attacker_node = attacker_node
        self.non_target_nodes = {attacker_node}
        self.best_state: Optional[AttackState] = None
        self.prev_map: Dict[AttackState, Tuple[AttackState, str]] = {}
        self.visited_states_count = 0
        self.total_nodes = len(self.nodes) - len(self.non_target_nodes)
    
    def _check_firewall_access(self, source_node: str, target_node: str, port: str) -> bool:
        """Check if firewall rules allow access from source to target on given port"""
        if source_node not in self.nodes or target_node not in self.nodes:
            return False
        if source_node == target_node:
            return True
        
        source_info = self.nodes[source_node]
        target_info = self.nodes[target_node]
        
        # Get IP addresses
        source_ip = "0.0.0.0"
        if source_info.network_info and len(source_info.network_info) > 0:
            source_ip = source_info.network_info[0].ip_address
        
        target_ip = "0.0.0.0"
        if target_info.network_info and len(target_info.network_info) > 0:
            target_ip = target_info.network_info[0].ip_address
        
        # Check outgoing rules
        outgoing_allowed = False
        for rule in source_info.firewall.outgoing:
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
            # print(rule.permission,str(rule.subnet),source_ip)
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
    
    def _get_available_actions(self, state: AttackState):
        """Generate all possible actions from current state"""
        global IS_DEBUG
        attack_actions = []
        movement_actions = []
        is_debug= state.current_destination=='node-worker-000'
        if is_debug:
            IS_DEBUG=True
        # Attack actions from current source
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
                
                target_info = self.nodes[state.current_destination]
                
                # Remote exploits
                for v_name, v_info in target_info.vulnerabilities.items():

                    if v_info.type == VulnerabilityType.REMOTE:
                        check_access=self._check_firewall_access(state.current_source, 
                                                       state.current_destination, "*")
                        if check_access:
                            attack_actions.append((
                                "remote_exploit",
                                state.current_source,
                                state.current_destination,
                                v_name,
                                v_info,
                                None
                            ))
                
                # Service connections (only if not owned yet)
                if state.current_destination not in state.owned_nodes:
                    for service in target_info.services:
                        if self._check_firewall_access(state.current_source, 
                                                       state.current_destination, 
                                                       service.name):
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
    
    def _apply_action(self, state: AttackState, action) -> Tuple[AttackState, float]:
        """Apply action to state and return new state with cost"""
        action_type, _, target_node, _, vuln_info, _ = action
        
        if action_type == "change_source":
            return state.apply_movement(new_source=target_node), 0.1
        
        elif action_type == "change_destination":
            return state.apply_movement(new_destination=target_node), 0.1
        
        elif vuln_info and vuln_info.outcome:
            cost = vuln_info.cost
            new_state = state.apply_outcome(target_node, vuln_info.outcome, self.nodes)
            return new_state, cost
        
        return state, 1.0
    
    def _get_better_state(self, s1: Optional[AttackState], 
                         s2: Optional[AttackState]) -> Optional[AttackState]:
        """Compare states and return the better one"""
        if not s1:
            return s2
        if not s2:
            return s1
        
        # Priority: Owned -> Known -> Credentials
        owned1 = s1.get_owned_count(self.non_target_nodes)
        owned2 = s2.get_owned_count(self.non_target_nodes)
        
        if owned1 > owned2:
            return s1
        if owned1 < owned2:
            return s2
        
        if len(s1.known_nodes) > len(s2.known_nodes):
            return s1
        if len(s1.known_nodes) < len(s2.known_nodes):
            return s2
        
        return s1 if len(s1.credentials) > len(s2.credentials) else s2
    
    def _dfs_explore_iterative(self, initial_state: AttackState, max_depth: int,
                               start_time: float, timeout: float, max_states: int):
        """
        Iterative depth-first search with prioritization using explicit stack.
        Continues until stack is empty (no more paths to explore).
        """
        # Stack contains tuples of (state, depth, action_iterator_index)
        # We'll use a different approach: store (state, depth) and generate actions on-demand
        stack = [(initial_state, 0)]
        visited = set()
        
        # Keep track of which actions we've tried for each state
        # Map from state to index of next action to try
        action_progress = {}
        
        # Track the last time we made progress
        last_progress_count = 0
        iterations_without_progress = 0
        max_iterations_without_progress = 1000  # Safety check
        
        while stack:
            # Check timeout and state limit (safety limits)
            if time.time() - start_time > timeout:
                raise SearchTimeoutError("Time limit exceeded")
            if self.visited_states_count >= max_states:
                raise SearchStateLimitError("State limit exceeded")
            
            current_state, depth = stack[-1]
            
            # Check depth limit
            if depth >= max_depth:
                stack.pop()
                continue
            
            # Mark as visited on first encounter
            if current_state not in visited:
                visited.add(current_state)
                self.visited_states_count += 1
                
                # Check if we made progress (better state found)
                old_best = self.best_state
                self.best_state = self._get_better_state(current_state, self.best_state)
                
                if self.best_state != old_best:
                    # We found a better state - reset no-progress counter
                    iterations_without_progress = 0
                    last_progress_count = self.visited_states_count
                else:
                    iterations_without_progress += 1
                
                if self.visited_states_count % 2000 == 0:
                    owned = self.best_state.get_owned_count(self.non_target_nodes) if self.best_state else 0
                    print(f"  Visited {self.visited_states_count} states. Best owned: {owned} {time.time() - start_time}/{timeout}")
                    print(f"  Last progress at state {last_progress_count}, iterations without progress: {iterations_without_progress}")
            
            # Get or generate actions for this state
            if current_state not in action_progress:
                actions = self._get_available_actions(current_state)
                
                # Sort actions: Attack/Connect first, then Change Destination, then Change Source
                actions.sort(key=lambda x: (
                    0 if x[0] == 'connect'
                    else (1 if x[0] in ['local_exploit', 'remote_exploit']
                    else (2 if x[0] in ['change_destination', 'change_source']
                    else 3))
                ))
                action_progress[current_state] = (actions, 0)
            
            actions, next_action_idx = action_progress[current_state]
            
            # If we've tried all actions for this state, backtrack
            if next_action_idx >= len(actions):
                stack.pop()
                # Clean up to save memory
                del action_progress[current_state]
                continue
            
            # Get next action to try
            action = actions[next_action_idx]
            action_progress[current_state] = (actions, next_action_idx + 1)
            
            # Apply the action
            new_state, _ = self._apply_action(current_state, action)
            
            # Check if this is ANY kind of progress (not just owned nodes)
            current_owned = current_state.get_owned_count(self.non_target_nodes)
            new_owned = new_state.get_owned_count(self.non_target_nodes)
            current_known = len(current_state.known_nodes)
            new_known = len(new_state.known_nodes)
            current_creds = len(current_state.credentials)
            new_creds = len(new_state.credentials)
            # Progress is made if we gain: new owned nodes, new known nodes, OR new credentials
            progress_made = (new_owned > current_owned or 
                           new_known > current_known or 
                           new_creds > current_creds)
            # Only explore if not visited or if progress was made
            if new_state not in visited or progress_made:
                label = (f"{action[0]} {action[3].split()[-1] if 'Change' in action[3] else action[3]}")
                print(label)
                self.prev_map[new_state] = (current_state, label)
                
                # If we made any progress, abandon all other paths
                # and continue only from this successful path
                if progress_made:
                    progress_type = []
                    if new_owned > current_owned:
                        progress_type.append(f"owned: {current_owned}->{new_owned}")
                    if new_known > current_known:
                        progress_type.append(f"known: {current_known}->{new_known}")
                    if new_creds > current_creds:
                        progress_type.append(f"creds: {current_creds}->{new_creds}")
                    
                    print(f"BREAKTHROUGH! Progress made: {', '.join(progress_type)}")
                    print(f"Clearing stack and continuing only from this successful path")
                    
                    # Clear the entire stack
                    stack.clear()
                    
                    # Clear action progress for all states except those in current path
                    # This forces re-exploration from the new successful state
                    action_progress.clear()
                    
                    # Reset no-progress counter since we made a breakthrough
                    iterations_without_progress = 0
                    
                    # Start fresh from the new winning state
                    stack.append((new_state, depth + 1))
                else:
                    # Normal exploration - just push new state onto stack
                    stack.append((new_state, depth + 1))
        
        # If we exit the loop, the stack is empty - we've explored all possibilities
        print(f"Search exhausted all paths. Total states visited: {self.visited_states_count}")
        owned = self.best_state.get_owned_count(self.non_target_nodes) if self.best_state else 0
        print(f"Final best state owns {owned}/{self.total_nodes} nodes")
    
    def solve(self, max_depth: int = 50, timeout_sec: float = 60, 
             max_visited_states: int = 100000) -> Dict:
        """
        Solve for optimal attack path using iterative DFS.
        Continues until no new progress is found (stack is empty).
        
        Args:
            max_depth: Maximum search depth
            timeout_sec: Maximum time in seconds (safety limit)
            max_visited_states: Maximum states to visit (safety limit)
            
        Returns:
            Dictionary with attack path results
        """
        # No need to set recursion limit since this is iterative
        
        start = time.time()
        initial_state = AttackState.create_initial(self.attacker_node, self.nodes)
        print(initial_state)
        self.best_state = initial_state
        self.prev_map = {initial_state: (None, "Initial State")}
        self.visited_states_count = 0
        
        try:
            self._dfs_explore_iterative(initial_state, max_depth, 
                                       start, timeout_sec, max_visited_states)
            # If we get here, the stack became empty - natural termination
            print("Search completed: No more paths to explore (stack empty)")
        except (SearchTimeoutError, SearchStateLimitError) as e:
            print(f"Search stopped by safety limit: {e}")
        
        return self._reconstruct_path_to_state(self.best_state, time.time() - start)
    
    def _reconstruct_path_to_state(self, best_state: AttackState, duration: float) -> Dict:
        """Reconstruct the path to the best state found"""
        path = []
        current = best_state
        
        while current in self.prev_map and self.prev_map[current][0] is not None:
            parent, action = self.prev_map[current]
            path.append(action)
            current = parent
        
        path.reverse()
        total_value=sum([self.nodes[n].value for n in best_state.get_owned(self.non_target_nodes)])
        return {
            "maximal_achievement": {
                "path": path,
                "nodes_owned": best_state.get_owned_count(self.non_target_nodes),
                "value":total_value,
                "total_target_nodes": self.total_nodes,
                "starting_node": self.attacker_node,
                "computation_time": f"{duration:.2f}s",
                "best_state": best_state.to_dict()
            }
        }