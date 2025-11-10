from cyberbattlesim_network_gen.network_generators.toyctf.toy_ctf import ToyCTFNetworkGenerator
from cyberbattlesim_experiments.common import ascii_utils, scenario_utils
from cyberbattlesim_experiments.common.configs import ds
from cyberbattlesim_experiments.common.scenario_utils import save_scenario
import copy
import pandas as pd
import networkx as nx
from tqdm import tqdm
from cyberbattle._env.DynamicEnviroment import CyberBattleCustomDynamic
import random
import numpy as np
from cyberbattlesim_experiments.common.eda import to_graph
import os # Added for file example

class InteractivePenTesting:
    def __init__(self, env):
        self.env = env
        self.reset()
        
    def reset(self):
        self.env.reset()
        self.action_mask = self.env.action_masks()
        self.actions = [a for a in range(self.env.action_space.n) if self.action_mask[a] == 1]
        self.stats = {
            'ActionName': [],
            'ActionIndex': [],
            'reward': [],
            'discovered_nodes': [],
            'owned_nodes_ratio': [],
            'owned_nodes': [],
            'done': [],
            'Source': [],
            'Target': [],
        }
        self.done = False
        self.total_reward = 0
        self.current_step = 0
        
    def get_available_actions(self):
        """Get list of available actions with descriptions"""
        # Update action mask in case it changed
        self.action_mask = self.env.action_masks()
        self.actions = [a for a in range(self.env.action_space.n) if self.action_mask[a] == 1]
        
        available_actions = []
        for action in self.actions:
            action_name = self.env.get_action_name(action)
            available_actions.append({
                'index': action,
                'name': action_name,
                'description': f"Action {action}: {action_name}"
            })
        return available_actions
    
    def get_network_info(self):
        """Get current network state information"""
        nodes = list(self.env.environment.nodes())
        discovered = self.env.discovered_nodes()
        owned = self.env.get_owned_nodes()
        
        return {
            'total_nodes': len(nodes),
            'discovered_nodes': len(discovered),
            'owned_nodes': len(owned),
            'owned_ratio': len(owned) / len(nodes) if nodes else 0,
            'discovered_node_list': discovered,
            'owned_node_list': owned
        }
    
    def get_current_state(self):
        """Get current game state summary"""
        network_info = self.get_network_info()
        return {
            'step': self.current_step,
            'total_reward': self.total_reward,
            'done': self.done,
            'network': network_info,
            'available_actions': len(self.get_available_actions())
        }
    
    def execute_action(self, action_or_actions):
        """Execute a specific action or a list of actions"""
        
        # Make sure actions are up to date
        self.get_available_actions()

        # Normalize input to a list
        if isinstance(action_or_actions, int):
            action_list = [action_or_actions]
            was_single_int = True
        elif isinstance(action_or_actions, list):
            action_list = action_or_actions
            was_single_int = False
        else:
            print(f"Invalid input. Expected int or list, got {type(action_or_actions)}")
            return None
        visible_observation, reward, done, info=None,None,None,None
        results = []
        
        for action_index in action_list:
            if self.done:
                print("Episode is already completed! Reset to start new episode.")
                break  # Stop processing the list if the episode is done
                
            if action_index not in self.actions:
                print(f"Action {action_index} is not available! Skipping.")
                results.append(None)
                continue
                
            # Execute the action
            visible_observation, reward, done, info = self.env.step(action_index)
            self.total_reward += reward
            self.done = done
            
            # Record stats
            self.stats['ActionName'].append(self.env.get_action_name(action_index))
            self.stats['Source'].append(self.env.get_selected_source())
            self.stats['Target'].append(self.env.get_selected_target())
            self.stats['ActionIndex'].append(action_index)
            self.stats['discovered_nodes'].append(len(self.env.discovered_nodes()))
            self.stats['owned_nodes'].append(len(self.env.get_owned_nodes()))
            self.stats['owned_nodes_ratio'].append(len(self.env.get_owned_nodes()) / len(list(self.env.environment.nodes())))
            self.stats['reward'].append(self.total_reward)
            self.stats['done'].append(int(done))
            
            self.current_step += 1
            
            result = {
                'action': self.env.get_action_name(action_index),
                'reward': reward,
                'total_reward': self.total_reward,
                'done': done,
                'source': self.env.get_selected_source(),
                'target': self.env.get_selected_target(),
                'step': self.current_step,
                'owned_nodes': len(self.env.get_owned_nodes()),
                'discovered_nodes': len(self.env.discovered_nodes()),
                
                'outcome':info['outcome'],
            }
            results.append(result)

        # Return a single item if a single int was passed, else return the list
        if was_single_int:
            return results[0] if results else None
        else:
            return results
    
        
    def get_statistics(self):
        """Get detailed statistics"""
        return pd.DataFrame.from_dict(self.stats)
    
    def auto_explore(self, steps=10):
        """Automatically explore for a number of steps"""
        results = []
        for i in range(steps):
            if self.done:
                print(f"Episode completed at step {self.current_step}")
                break
                
            # Choose random action
            # Update available actions first
            self.get_available_actions()
            if not self.actions:
                print("No available actions to auto-explore.")
                break
            for action in self.actions[:-4]:
                result = self.execute_action(action)
                results.append(result)
        
        return results

# --- Helper Functions for Session ---

def print_current_state(pentester):
    """Prints the summary state and returns 'done' status"""
    state = pentester.get_current_state()
    network = state['network']
    
    print("\n" + "=" * 50)
    print(f"STEP {state['step']} - Total Reward: {state['total_reward']:.2f}")
    print("=" * 50)
    print(f"Network State:")
    print(f"  Total Nodes: {network['total_nodes']}")
    print(f"  Discovered: {network['discovered_nodes']}")
    print(f"  Owned: {network['owned_nodes']}")
    print(f"  Control Ratio: {network['owned_ratio']:.2%}")
    print(f"  Available Actions: {state['available_actions']}")
    
    return state['done']

def print_detailed_stats(pentester):
    """Prints the full statistics dataframe"""
    stats_df = pentester.get_statistics()
    if not stats_df.empty:
        print("\n--- Detailed Statistics ---")
        print(stats_df.to_string(index=False))
        print("---------------------------")
    else:
        print("\n--- No statistics available yet ---")

def process_command(pentester, user_input):
    """
    Processes a single command string for the pentester.
    Returns False if 'quit' is commanded, True otherwise.
    """
    if user_input == 'quit' or user_input == 'exit':
        return False # Signal to stop
        
    elif user_input == 'list':
        actions = pentester.get_available_actions()
        print("\nAvailable Actions:")
        for action in actions:
            print(f"  {action['description']}")
            
    elif user_input.startswith('execute '):
        try:
            action_strings = user_input.split()[1:]
            if not action_strings:
                print("No action index provided. Usage: execute <index1> [index2] ...")
                return True
                
            action_indices = [int(a) for a in action_strings]
            
            if len(action_indices) == 1:
                results = pentester.execute_action(action_indices[0]) # Pass int
            else:
                results = pentester.execute_action(action_indices) # Pass list
            
            if not results:
                print("Action(s) could not be executed.")
                return True

            # Normalize results to a list for consistent printing
            if not isinstance(results, list):
                results_list = [results]
            else:
                results_list = results
                
            print(f"\nAction Result(s):")
            for result in results_list:
                if result:
                    print("-" * 20)
                    print(f"  Action: {result['action']}")
                    print(f"  Step: {result['step']}")
                    print(f"  Step Reward: {result['reward']:.2f}")
                    print(f"  Total Reward: {result['total_reward']:.2f}")
                    print(f"  Source: {result['source']}")
                    print(f"  Target: {result['target']}")
                    if result['done']:
                        print("  🎯 EPISODE COMPLETED!")
                else:
                    print("-" * 20)
                    print("  Action skipped or failed (not available or episode done).")
                    
        except (ValueError, IndexError):
            print("Invalid command. Usage: execute <index1> [index2] ...")
            
    elif user_input.startswith('auto '):
        try:
            steps = int(user_input.split()[1])
            print(f"Auto-exploring for {steps} steps...")
            results = pentester.auto_explore(steps)
            print(f"Completed {len(results)} steps")
        except (ValueError, IndexError):
            print("Invalid command. Usage: auto <steps>")
            
    elif user_input == 'stats':
        # This is now redundant, but we keep it so it doesn't show "Unknown command"
        print("Detailed stats are printed automatically.")
        # We can force a reprint if desired
        # print_detailed_stats(pentester) 
                
    elif user_input == 'reset':
        pentester.reset()
        print("Environment reset!")
        
    else:
        print(f"Unknown command: '{user_input}'")
    
    return True # Signal to continue

# --- Main Session Function ---

def interactive_pentest_session(environment_name="KubernetesCluster-v0", command_file=None):
    """
    Start a pentesting session.
    If command_file is provided, runs non-interactively from the file.
    Otherwise, runs in interactive mode.
    """
    
    # Initialize environment
    try:
        # /content/drive/MyDrive/thesis/code/datasets/poc/generated/CyberBattleTinyToy-Spectral3-v0/identifiers/identifiers.yaml
        env = scenario_utils.get_env(environment_name,
                                     ds,
                                     global_identifiers_path=f'{ds.generated}/{environment_name}/identifiers/identifiers.yaml')
        pentester = InteractivePenTesting(env.env)
        pentester.env.move_target_through_owned=True
    except Exception as e:
        print(f"Failed to initialize environment: {e}")
        return None
    import json
    nodes_owned=-1
    with open(f'{ds.generated}/{environment_name}/analysis/attack_paths.json') as f:
        m=json.load(f)['maximal_achievement']
        nodes_owned=m['nodes_owned']
        steps=m['steps']
        
    for step in steps:
        print(step)
        if 'Local'.lower() in step.lower() and 'exploit'  in step.lower():
            step=step.replace('Local exploit ','')
            step=step[:step.index(' on ')]
            pentester.execute_action(env.env.action_name_to_id(step))
        elif 'Remote exploit' in step:
            step=step.replace('Remote exploit ','')
            step=step[:step.index(' from ')]
            print(pentester.execute_action(env.env.action_name_to_id(step)))
        elif 'Change source' in step:
            'Change source from attacker to node-worker-000'
            step=step.replace('Change source from ','')
            src=step[:step.index(' ')]
            dst=step[step.index(' to ')+4:]
            # print(src,dst,env.env.source_node_index,env.env.target_node_index)
            not_done=True
            t=10
            while not_done:
                source_node_index_before=env.env.source_node_index
                target_node_index_before=env.env.target_node_index
                r=pentester.execute_action(len(env.env.get_actions())-4)
                if target_node_index_before==env.env.target_node_index and env.env.source_node_index==dst:
                    not_done=False
                    # print('changed src')
                    # print(r)
                     
                else:
                    # pentester.execute_action(len(env.env.get_actions())-1)
                    t-=1
                    if t<0:
                        x=7/0
                            



        elif 'Change destination' in step:
            step=step.replace('Change destination from ','')
            src=step[:step.index(' ')]
            dst=step[step.index(' to ')+4:]
            not_done=True
            
            t=10
            while not_done:
                source_node_index_before=env.env.source_node_index
                target_node_index_before=env.env.target_node_index
                r=pentester.execute_action(len(env.env.get_actions())-1)
                print(r)
                # r=pentester.execute_action(len(env.env.get_actions())-2)
                # print('[info][dst]',src,'->',dst,'src:',y,'->',env.env.source_node_index,'dst',x,'->',env.env.target_node_index)
                # print(src==x)
                # print(env.env.target_node_index==dst)
                if source_node_index_before==env.env.source_node_index and env.env.target_node_index==dst:
                    not_done=False
                else:
                    # pentester.execute_action(len(env.env.get_actions())-1)
                    t-=1
                    if t<0:
                        x=7/0
                    
                print("dst")
                # print(step)
                # print(src,dst,env.env.source_node_index,env.env.target_node_index)
                # if env.env.target_node_index==dst:
                #     break
            
            # print(src,dst,env.env.source_node_index,env.env.target_node_index)
            
        else:
            x=1/0
    correct=len(pentester.env.get_owned_nodes())==nodes_owned+1
    if not correct:
        print(len(pentester.env.get_owned_nodes())==nodes_owned+1)
        print(pentester.env.get_owned_nodes(),nodes_owned+1)
        raise Exception('erro')
    return
    print("=" * 60)
    print("INTERACTIVE PENETRATION TESTING SIMULATION")
    print("=" * 60)
    print(f"Environment: {environment_name}")
    print()
    
    if command_file:
        # --- NON-INTERACTIVE (FILE) MODE ---
        print(f"Running in non-interactive mode from file: {command_file}")
        try:
            with open(command_file, 'r') as f:
                commands = f.readlines()
            
            for line in commands:
                user_input = line.strip().lower()
                # Skip blank lines and comments
                if not user_input or user_input.startswith('#'):
                    continue

                # Print current state and stats *before* executing command
                done = print_current_state(pentester)
                print_detailed_stats(pentester)

                if done:
                    print("\n🎯 EPISODE COMPLETED! Halting file processing.")
                    break
                
                print(f"\n>>> Executing command from file: {user_input}")
                
                # Process the command
                keep_going = process_command(pentester, user_input)
                if not keep_going:
                    print("'quit' command encountered. Stopping.")
                    break
        
        except FileNotFoundError:
            print(f"Error: Command file not found at {command_file}")
        except Exception as e:
            print(f"Error during file processing: {e}")

    else:
        # --- INTERACTIVE MODE ---
        print("Running in interactive mode.")
        while True:
            # Print current state and stats *before* prompt
            done = print_current_state(pentester)
            print_detailed_stats(pentester)
            
            if done:
                print("\n🎯 EPISODE COMPLETED!")
                break
            
            # Show menu
            print("\nAvailable Commands:")
            print("1. list - Show available actions")
            print("2. execute <index1> [index2] ... - Execute one or more actions")
            print("3. auto <steps> - Auto-explore for N steps")  
            print("4. stats - (Now prints automatically)")
            print("5. movesource <direction> - Move source node (1 or -1)")
            print("6. movetarget <direction> - Move target node (1 or -1)")
            print("7. reset - Reset environment")
            print("8. quit - Exit simulation")
            
            try:
                user_input = input("\nEnter command: ").strip().lower()
                
                keep_going = process_command(pentester, user_input)
                if not keep_going:
                    break # User typed 'quit'
                    
            except KeyboardInterrupt:
                print("\n\nSimulation interrupted by user.")
                break
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
    
    # Final statistics
    print("\n" + "=" * 60)
    print("FINAL STATISTICS")
    print("=" * 60)
    final_stats = pentester.get_statistics()
    if not final_stats.empty:
        print(final_stats.to_string(index=False))
    else:
        print("No actions were performed.")
    
    return pentester

# (can_solve_better_interactive remains the same)
def can_solve_better_interactive(env, max_repeats=40, owned_nodes_ratio=None, owned_nodes=None):
    """Interactive version of can_solve_better"""
    print(f"[Interactive Mode] Evaluating environment...")
    env.reset()
    pentester = InteractivePenTesting(env.env)
    
    print("Starting interactive session. Type 'quit' to exit or use auto mode.")
    # This function will now run interactively by default
    interactive_pentest_session() 
    
    # After interactive session, check if goals were met
    stats = pentester.get_statistics()
    if not stats.empty:
        if owned_nodes_ratio is not None:
            if max(list(stats['owned_nodes_ratio'])) > owned_nodes_ratio:
                return 1
        if owned_nodes is not None:
            if max(list(stats['owned_nodes'])) > owned_nodes:
                return 1
    return 0

# --- Main execution block ---
if __name__ == "__main__":
    
    # # --- EXAMPLE 1: Run from command file ---
    #  [
    #   "InitialScan on attacker",
    #   "Exploit_cassandra_0 on node-worker-000",
    #   "Exploit_cassandra_1 on node-worker-000",
    #   "Exploit_cassandra_2 on node-worker-000",
    #   "Exploit_cassandra_3 on node-worker-000",
    #   "Exploit_mongodb_0 on node-worker-000",
    #   "CVE-2025-0725_0 on node-worker-000",
    #   "CVE-2023-4016_0 on node-worker-000",
    #   "Exploit_etcd_0 on node-control_plane-000",
    #   "CVE-2022-0563_0 on node-control_plane-000",
    #   "CVE-2024-10041_0 on node-worker-000",
    #   "Exploit_etcd_1 on node-control_plane-001",
    #   "CVE-2022-0563_1 on node-control_plane-001",
    #   "Exploit_etcd_2 on node-control_plane-002",
    #   "CVE-2022-0563_2 on node-control_plane-002"
    # ]
    # Create a dummy command file
    command_file_name = "my_attack_plan.txt"
    with open(command_file_name, "w") as f:
        f.write("# My attack plan\n")
        f.write("list\n")
        # f.write("list\n") # See new actions
        f.write("execute 15\n") # See new actions
        f.write("execute 16\n") # See new actions
        f.write("execute 269\n") # See new actions
        f.write("execute 139\n") # See new actions
        f.write("execute 140\n") # See new actions
        f.write("execute 141\n") # See new actions
        f.write("execute 142\n") # See new actions
        f.write("execute 167\n") # See new actions
        f.write("execute 104\n") # See new actions
        f.write("execute 26\n") # See new actions
        for p in range(199,211):
            f.write(f"execute {p}\n") # See new actions
        f.write("execute 269\n") # See new actions
        for p in range(0,199):
            f.write(f"execute {p}\n") # See new actions
        f.write("execute 269\n") # See new actions
        for p in range(0,199):
            f.write(f"execute {p}\n") # See new actions
        for p in range(199,211):
            f.write(f"execute {p}\n") # See new actions
        f.write("execute 269\n") # See new actions
        for p in range(199,211):
            f.write(f"execute {p}\n") # See new actions

        f.write("execute 269\n") # See new actions
        for p in range(0,199):
            f.write(f"execute {p}\n") # See new actions
        for p in range(199,211):
            f.write(f"execute {p}\n") # See new actions
        # f.write("execute 269\n") # See new actions
        # for p in range(199,211):
            # f.write(f"execute {p}\n") # See new actions

        f.write("stats\n") # See new actions
        # f.write("list\n") # See new actions
        # f.write("auto 3\n")
        f.write("quit\n") # End the simulation
        
    print(f"--- Running simulation from file: {command_file_name} ---")
    # CyberBattleTinyToy-Spectral3-v0
    pentester_file = interactive_pentest_session("KubernetesCluster-v0", command_file=command_file_name)
    
    # Clean up the dummy file
    if os.path.exists(command_file_name):
        os.remove(command_file_name)
        
    print("\n\n" + "="*80 + "\n\n")

    # --- EXAMPLE 2: Run interactively (uncomment to use) ---
    
    # print("--- Running simulation in INTERACTIVE mode ---")
    # Start interactive session
    # pentester_interactive = interactive_pentest_session("KubernetesCluster-v0")