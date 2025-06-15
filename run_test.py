#!/usr/bin/env python3
"""
Testing Script
Runs different scenarios using docker commands
"""

import subprocess
import time
import json
import os
import signal
import threading
from datetime import datetime
from typing import Dict, List, Optional

class TestRunner:
    def __init__(self):
        self.results = []
        self.results_dir = "test_results"
        self.ensure_results_dir()
        self.processor_pid = None
        self.receiver_pid = None
        self.sender_pid = None
        self.generator_pid = None
        self.processor_type = "tppphase2"  # Default processor
        
    def ensure_results_dir(self):
        """Create results directory"""
        os.makedirs(self.results_dir, exist_ok=True)
        
    def run_docker_command(self, container: str, command: str, background: bool = False, silent: bool = False) -> Optional[subprocess.Popen]:
        """Run a docker command"""
        # Use -i instead of -it for background processes to avoid TTY issues
        docker_flag = "-i" if background else "-it"
        full_command = f"docker exec {docker_flag} {container} {command}"
        
        if not silent:
            print(f"Running: {full_command}")
        
        if background:
            return subprocess.Popen(
                full_command.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
        else:
            result = subprocess.run(
                full_command.split(),
                capture_output=True,
                text=True,
                timeout=60  # Reduce timeout for non-background commands
            )
            return result
    
    def start_processor(self) -> subprocess.Popen:
        """Start the processor in background"""
        processor_files = {
            "tppphase2": "/code/python-processor/tppphase2_main.py",
            "tppphase3": "/code/python-processor/tppphase3_main.py",
            "tppphase4": "/code/python-processor/tppphase4_main.py"
        }
        
        processor_file = processor_files.get(self.processor_type, processor_files["tppphase2"])
        print(f"Starting {self.processor_type} processor ({processor_file})...")
        
        proc = self.run_docker_command(
            "python-processor",
            f"python3 {processor_file}",
            background=True
        )
        time.sleep(3)  # Give processor time to start
        return proc
    
    def start_receiver(self, bits: int = 16, decrypt: bool = True) -> subprocess.Popen:
        """Start TPPhase2 receiver"""
        decrypt_flag = "--decrypt" if decrypt else ""
        command = f"python3 /code/insec/tppphase2_receiver.py --output ./received_files --bits {bits} {decrypt_flag}".strip()
        
        print(f"Starting receiver: bits={bits}, decrypt={decrypt}")
        return self.run_docker_command("insec", command, background=True)
    
    def start_sender(self, file_path: str, bits: int = 16, interval: float = 0.2, encrypt: bool = True) -> subprocess.Popen:
        """Start TPPhase2 sender"""
        encrypt_flag = "--encrypt" if encrypt else ""
        command = f"python3 /code/sec/tppphase2_sender.py --file {file_path} --interval {interval} --bits {bits} {encrypt_flag}".strip()
        
        print(f"Starting sender: file={file_path}, bits={bits}, interval={interval}, encrypt={encrypt}")
        return self.run_docker_command("sec", command, background=True)
    
    def start_traffic_receiver(self) -> subprocess.Popen:
        """Start legitimate traffic receiver"""
        print("Starting traffic receiver...")
        return self.run_docker_command("insec", "python3 /code/insec/traffic_receiver.py", background=True)
    
    def start_traffic_generator(self) -> subprocess.Popen:
        """Start legitimate traffic generator"""
        print("Starting traffic generator...")
        return self.run_docker_command("sec", "python3 /code/sec/traffic_generator.py", background=True)
    
    def stop_process(self, proc: Optional[subprocess.Popen], name: str):
        """Stop a process safely"""
        if proc and proc.poll() is None:
            print(f"Stopping {name}...")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    
    def restart_docker_environment(self):
        """Restart docker compose environment for clean state"""
        print("Restarting docker environment...")
        
        try:
            # Docker compose down
            print("Running docker compose down...")
            result_down = subprocess.run(
                ["docker", "compose", "down"],
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result_down.returncode != 0:
                print(f"Warning: docker compose down failed: {result_down.stderr}")
            else:
                print("Docker compose down completed")
            
            # Wait a moment
            time.sleep(3)
            
            # Docker compose up
            print("Running docker compose up -d...")
            result_up = subprocess.run(
                ["docker", "compose", "up", "-d"],
                capture_output=True,
                text=True,
                timeout=180  # 3 minutes for containers to start
            )
            
            if result_up.returncode != 0:
                print(f"Error: docker compose up failed: {result_up.stderr}")
                return False
            else:
                print("Docker compose up completed")
            
            # Wait for containers to be ready
            print("Waiting for containers to be ready...")
            time.sleep(10)
            
            # Verify containers are running
            result_ps = subprocess.run(
                ["docker", "ps"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result_ps.returncode == 0:
                required_containers = ["python-processor", "sec", "insec"]
                for container in required_containers:
                    if container not in result_ps.stdout:
                        print(f"Error: {container} container not running after restart")
                        return False
                print("All containers verified running ✓")
                return True
            else:
                print("Error: Could not verify container status")
                return False
                
        except subprocess.TimeoutExpired:
            print("Error: Docker command timed out")
            return False
        except Exception as e:
            print(f"Error restarting docker environment: {e}")
            return False
    
    def clean_result_files(self):
        """Ensure result directories exist (no file removal)"""
        print("Ensuring result directories exist...")
        
        try:
            # Ensure directories exist
            os.makedirs("code/insec/received_files", exist_ok=True)
            os.makedirs("code/python-processor/benchmark_results", exist_ok=True)
            
            print("  Result directories verified ✓")
            print("Directory setup completed")
            return True
            
        except Exception as e:
            print(f"Error setting up result directories: {e}")
            return False
    
    def wait_for_file_transmission(self, receiver_proc: subprocess.Popen, sender_proc: subprocess.Popen, timeout: int = 180) -> bool:
        """Wait for file transmission to complete"""
        start_time = time.time()
        files_before = set()
        
        # Get initial file list
        try:
            result = self.run_docker_command("insec", "ls /code/insec/received_files/", silent=True)
            if result and result.stdout:
                files_before = set(result.stdout.strip().split('\n'))
        except:
            pass
        
        print(f"Monitoring file transmission (timeout: {timeout}s)...")
        
        while time.time() - start_time < timeout:
            elapsed = time.time() - start_time
            
            # Check if sender process finished (more reliable than receiver)
            if sender_proc and sender_proc.poll() is not None:
                print(f"Sender process finished after {elapsed:.1f}s - file transmission complete")
                time.sleep(3)  # Give receiver time to process last packets
                return True
            
            # Check for new files in received_files directory
            try:
                result = self.run_docker_command("insec", "ls /code/insec/received_files/", silent=True)
                if result and result.stdout and "received_file_" in result.stdout:
                    files_after = set(result.stdout.strip().split('\n'))
                    new_files = files_after - files_before
                    if new_files:
                        print(f"New file detected: {new_files}")
                        return True
                        
                        # Update files_before for next iteration
                        files_before = files_after
            except Exception as e:
                print(f"Error checking files: {e}")
            
            # Check receiver process output for completion messages
            if receiver_proc and receiver_proc.poll() is not None:
                print(f"Receiver process finished after {elapsed:.1f}s")
                time.sleep(2)
                return True
            
            # Print progress every 40 seconds
            if int(elapsed) % 40 == 0 and int(elapsed) > 0:
                print(f"Still waiting... {elapsed:.0f}s elapsed")
            
            time.sleep(5)
        
        print(f"File transmission timeout after {timeout} seconds")
        
        # Debug: Show process states
        if sender_proc:
            print(f"Sender process state: {sender_proc.poll()}")
        if receiver_proc:
            print(f"Receiver process state: {receiver_proc.poll()}")
            
        # Debug: Show final file state
        try:
            result = self.run_docker_command("insec", "ls -la /code/insec/received_files/")
            if result:
                print(f"Final received_files state:\n{result.stdout}")
        except:
            pass
            
        return False
    
    def get_processor_results(self) -> Optional[Dict]:
        """Get results from the processor"""
        # TPPhase2 uses metadata files from received_files folder
        if self.processor_type == "tppphase2":
            print("TPPhase2: Looking for metadata files in received_files folder")
            try:
                import glob
                
                # Look for metadata files in the received_files directory
                metadata_pattern = "code/insec/received_files/*_metadata.json"
                metadata_files = glob.glob(metadata_pattern)
                
                if not metadata_files:
                    print("No metadata files found in received_files")
                    return {
                        'processor_type': 'tppphase2',
                        'description': 'Covert channel implementation',
                        'note': 'No metadata files found - transmission may have failed'
                    }
                
                # Get the most recent metadata file
                metadata_files.sort(key=os.path.getmtime, reverse=True)
                latest_metadata = metadata_files[0]
                
                print(f"Reading TPPhase2 results from: {latest_metadata}")
                
                try:
                    with open(latest_metadata, 'r') as f:
                        metadata = json.load(f)
                    
                    # Enhance metadata with processor type info
                    metadata['processor_type'] = 'tppphase2'
                    metadata['description'] = 'Covert channel transmission results'
                    
                    return metadata
                    
                except json.JSONDecodeError as e:
                    print(f"Error parsing metadata JSON: {e}")
                    return None
                except Exception as e:
                    print(f"Error reading metadata file {latest_metadata}: {e}")
                    return None
                    
            except Exception as e:
                print(f"Error getting TPPhase2 metadata: {e}")
                return {
                    'processor_type': 'tppphase2',
                    'description': 'Covert channel implementation',
                    'error': str(e)
                }
        
        try:
            import glob
            
            # Check if directory exists on local filesystem
            results_dir = "code/python-processor/benchmark_results"
            if not os.path.exists(results_dir):
                print("Benchmark results directory not found")
                return None
            
            # Find the latest result file based on processor type
            if self.processor_type == "tppphase4":
                pattern = os.path.join(results_dir, "urg_mitigation_*.json")
                file_type = "urg_mitigation"
            else:
                pattern = os.path.join(results_dir, "detection_session_*.json")
                file_type = "detection_session"
            
            files = glob.glob(pattern)
            if not files:
                print(f"No {file_type} JSON files found in {results_dir}")
                return None
            
            # Sort by modification time to get the most recent file
            files.sort(key=os.path.getmtime, reverse=True)
            latest_file = files[0]
            
            print(f"Reading processor results from: {latest_file}")
            
            # Read the result file directly from filesystem
            try:
                with open(latest_file, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                print(f"Error parsing JSON from processor results: {e}")
                return None
            except Exception as e:
                print(f"Error reading processor result file {latest_file}: {e}")
                return None
            
        except Exception as e:
            print(f"Error getting processor results: {e}")
        
        return None
    
    def run_test_scenario(self, scenario: Dict) -> Dict:
        """Run a single test scenario"""
        print(f"\n{'='*60}")
        print(f"Running Test: {scenario['name']}")
        print(f"Description: {scenario['description']}")
        print(f"{'='*60}")
        
        test_result = {
            'scenario': scenario,
            'timestamp': datetime.now().isoformat(),
            'status': 'started'
        }
        
        processor_proc = None
        receiver_proc = None
        sender_proc = None
        traffic_receiver_proc = None
        traffic_generator_proc = None
        
        try:
            # Start processor first
            processor_proc = self.start_processor()
            
            # Start background legitimate traffic for processors that need it
            # TPPhase2 should have NO TRAFFIC except covert channel
            if self.processor_type != "tppphase2":
                print("Starting background legitimate traffic...")
                traffic_receiver_proc = self.start_traffic_receiver()
                time.sleep(2)
                traffic_generator_proc = self.start_traffic_generator()
                time.sleep(2)
            else:
                print("TPPhase2 covert channel: NO TRAFFIC except covert channel packets")
            
            # Start covert channel receiver if needed
            if scenario['type'] in ['covert', 'mixed']:
                receiver_proc = self.start_receiver(
                    bits=scenario.get('covert_params', {}).get('bits', 16),
                    decrypt=scenario.get('covert_params', {}).get('encrypt', True)
                )
                time.sleep(2)
            
            # Start covert channel sender if needed
            if scenario['type'] in ['covert', 'mixed']:
                covert_params = scenario.get('covert_params', {})
                sender_proc = self.start_sender(
                    file_path=covert_params.get('file', './secret_message.txt'),
                    bits=covert_params.get('bits', 16),
                    interval=covert_params.get('interval', 0.2),
                    encrypt=covert_params.get('encrypt', True)
                )
            
            # Wait for completion
            if scenario['type'] in ['covert', 'mixed']:
                print("Waiting for file transmission to complete...")
                transmission_success = self.wait_for_file_transmission(receiver_proc, sender_proc)
                test_result['transmission_success'] = transmission_success
            elif scenario['type'] == 'baseline':
                # For baseline tests (no traffic), run for a fixed duration
                duration = scenario.get('duration', 30)
                print(f"Running baseline test for {duration} seconds...")
                time.sleep(duration)
                test_result['transmission_success'] = True
            else:
                # For other traffic types, run for a fixed duration
                duration = scenario.get('duration', 30)
                print(f"Running traffic test for {duration} seconds...")
                time.sleep(duration)
                test_result['transmission_success'] = True
            
            # Get processor results
            print("Collecting processor results...")
            if self.processor_type == "tppphase2":
                # TPPhase2 doesn't need time to generate results
                processor_results = self.get_processor_results()
            else:
                time.sleep(10)  # Give other processors time to generate results
                processor_results = self.get_processor_results()
            
            if processor_results:
                test_result['processor_results'] = processor_results
                test_result['status'] = 'completed'
                print("Test completed successfully!")
            else:
                test_result['status'] = 'completed_no_results'
                print("Test completed but no processor results found")
            
        except Exception as e:
            print(f"Test failed: {e}")
            test_result['status'] = 'failed'
            test_result['error'] = str(e)
        
        finally:
            # Clean up all processes first
            self.stop_process(sender_proc, "sender")
            self.stop_process(receiver_proc, "receiver")
            self.stop_process(traffic_generator_proc, "traffic generator")
            self.stop_process(traffic_receiver_proc, "traffic receiver")
            self.stop_process(processor_proc, "processor")
            
            print("Test cleanup completed")
        
        return test_result
    
    def get_test_scenarios(self) -> List[Dict]:
        """Define test scenarios to run based on processor type and parameters"""
        
        # Base scenarios ordered by bits first, then encryption
        base_scenarios = [
            # 4-bit tests
            {
                'name': '4-bit Encrypted (0.2s)',
                'description': 'TPPhase2 covert channel: 4 bits, 0.2s interval, encrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 4,
                    'interval': 0.2,
                    'encrypt': True
                }
            },
            {
                'name': '4-bit Unencrypted (0.2s)',
                'description': 'TPPhase2 covert channel: 4 bits, 0.2s interval, unencrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 4,
                    'interval': 0.2,
                    'encrypt': False
                }
            },
            # 8-bit tests
            {
                'name': '8-bit Encrypted (0.2s)',
                'description': 'TPPhase2 covert channel: 8 bits, 0.2s interval, encrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 8,
                    'interval': 0.2,
                    'encrypt': True
                }
            },
            {
                'name': '8-bit Unencrypted (0.2s)',
                'description': 'TPPhase2 covert channel: 8 bits, 0.2s interval, unencrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 8,
                    'interval': 0.2,
                    'encrypt': False
                }
            },
            # 12-bit tests
            {
                'name': '12-bit Encrypted (0.2s)',
                'description': 'TPPhase2 covert channel: 12 bits, 0.2s interval, encrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 12,
                    'interval': 0.2,
                    'encrypt': True
                }
            },
            {
                'name': '12-bit Unencrypted (0.2s)',
                'description': 'TPPhase2 covert channel: 12 bits, 0.2s interval, unencrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 12,
                    'interval': 0.2,
                    'encrypt': False
                }
            },
            # 16-bit tests (0.2s)
            {
                'name': '16-bit Encrypted (0.2s)',
                'description': 'TPPhase2 covert channel: 16 bits, 0.2s interval, encrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 16,
                    'interval': 0.2,
                    'encrypt': True
                }
            },
            {
                'name': '16-bit Unencrypted (0.2s)',
                'description': 'TPPhase2 covert channel: 16 bits, 0.2s interval, unencrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 16,
                    'interval': 0.2,
                    'encrypt': False
                }
            },
            # 16-bit interval variations (encrypted)
            {
                'name': '16-bit Encrypted (0.1s)',
                'description': 'TPPhase2 covert channel: 16 bits, 0.1s interval, encrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 16,
                    'interval': 0.1,
                    'encrypt': True
                }
            },
            {
                'name': '16-bit Encrypted (0.5s)',
                'description': 'TPPhase2 covert channel: 16 bits, 0.5s interval, encrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 16,
                    'interval': 0.5,
                    'encrypt': True
                }
            },
            {
                'name': '16-bit Encrypted (1.0s)',
                'description': 'TPPhase2 covert channel: 16 bits, 1.0s interval, encrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 16,
                    'interval': 1.0,
                    'encrypt': True
                }
            },
            # 16-bit interval variation (unencrypted)
            {
                'name': '16-bit Unencrypted (0.1s)',
                'description': 'TPPhase2 covert channel: 16 bits, 0.1s interval, unencrypted',
                'type': 'covert',
                'covert_params': {
                    'file': './secret_message.txt',
                    'bits': 16,
                    'interval': 0.1,
                    'encrypt': False
                }
            }
        ]
        
        # For TPPhase2, only use covert channel scenarios (no additional traffic)
        if self.processor_type == "tppphase2":
            # TPPhase2 only needs covert channel tests - base_scenarios already contains them
            pass
        
        return base_scenarios
    
    def save_results(self, all_results: List[Dict]):
        """Save test results"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{self.results_dir}/test_results_{timestamp}.json"
        
        final_results = {
            'test_info': {
                'timestamp': timestamp,
                'total_tests': len(all_results),
                'successful_tests': len([r for r in all_results if r['status'] == 'completed']),
                'failed_tests': len([r for r in all_results if r['status'] == 'failed'])
            },
            'test_results': all_results
        }
        
        with open(filename, 'w') as f:
            json.dump(final_results, f, indent=2, default=str)
        
        print(f"\nResults saved to: {filename}")
        return filename
    
    def run_all_tests(self):
        """Run all test scenarios"""
        print("Parameter Testing for TPP Processors")
        print("=" * 60)
        
        scenarios = self.get_test_scenarios()
        print(f"Total scenarios to test: {len(scenarios)}")
        
        # Check prerequisites
        print("\nChecking prerequisites...")
        try:
            # Check if containers are running
            result = subprocess.run(["docker", "ps"], capture_output=True, text=True)
            if "python-processor" not in result.stdout:
                print("ERROR: python-processor container not running")
                return
            if "sec" not in result.stdout:
                print("ERROR: sec container not running")
                return
            if "insec" not in result.stdout:
                print("ERROR: insec container not running")
                return
            print("All containers are running ✓")
        except Exception as e:
            print(f"ERROR: Cannot check docker containers: {e}")
            return
        
        # Processor selection
        print(f"\nProcessor selection:")
        print("1. TPPhase2 - Covert Channel (default)")
        print("2. TPPhase3 - Covert Channel Detector")
        print("3. TPPhase4 - Covert Channel Mitigator")
        processor_choice = input("Select processor (1-3, default=1): ").strip()
        
        if processor_choice == "2":
            self.processor_type = "tppphase3"
            print("Selected: TPPhase3 Covert Channel Detector")
        elif processor_choice == "3":
            self.processor_type = "tppphase4"
            print("Selected: TPPhase4 Covert Channel Mitigator")
        else:
            self.processor_type = "tppphase2"
            print("Selected: TPPhase2 Covert Channel")
        
        # Test mode selection
        print(f"\nTest modes:")
        print("1. Run all scenarios")
        print("2. Run single test (debug mode)")
        print("3. Test docker commands only")
        mode = input("Select mode (1-3): ").strip()
        
        if mode == "3":
            self.test_docker_commands()
            return
        elif mode == "2":
            print("\nAvailable scenarios:")
            for i, scenario in enumerate(scenarios):
                print(f"{i+1}. {scenario['name']}")
            try:
                choice = int(input(f"Select scenario (1-{len(scenarios)}): ")) - 1
                if 0 <= choice < len(scenarios):
                    scenarios = [scenarios[choice]]
                else:
                    print("Invalid choice")
                    return
            except ValueError:
                print("Invalid input")
                return
        elif mode == "1":
            # Keep all scenarios for running all tests
            pass
        else:
            print("Invalid mode selection")
            return
        
        # Ask user confirmation
        if len(scenarios) == 1:
            print(f"\nReady to run the selected test scenario.")
            print("The test will:")
            print("1. Restart docker compose (down + up) for clean environment")
            print("2. Ensure result directories exist")
            if self.processor_type != "tppphase2":
                print("3. Start background legitimate traffic (traffic_generator & traffic_receiver)")
            else:
                print("3. NO TRAFFIC except covert channel packets (TPPhase2)")
            print("4. Collect processor results")
        else:
            print(f"\nReady to run all {len(scenarios)} test scenarios.")
            print("Each test will:")
            print("1. Restart docker compose (down + up) for clean environment")
            print("2. Ensure result directories exist")
            if self.processor_type != "tppphase2":
                print("3. Start background legitimate traffic (traffic_generator & traffic_receiver)")
            else:
                print("3. NO TRAFFIC except covert channel packets (TPPhase2)")
            print("4. Collect processor results and move to next test")
        
        response = input("Continue? (y/N): ").strip().lower()
        if response != 'y':
            print("Test cancelled")
            return
        
        # Run tests
        all_results = []
        for i, scenario in enumerate(scenarios):
            try:
                print(f"\n--- Test {i+1}/{len(scenarios)} ---")
                
                # Restart docker environment before each test for clean state
                if not self.restart_docker_environment():
                    print(f"Failed to restart docker environment for test {i+1}, skipping...")
                    continue
                
                # Ensure result directories exist
                if not self.clean_result_files():
                    print(f"Warning: Failed to setup result directories for test {i+1}, continuing anyway...")
                
                result = self.run_test_scenario(scenario)
                all_results.append(result)
                
                # Brief pause between tests (docker restart provides the main delay)
                if i < len(scenarios) - 1:
                    print("Preparing for next test...")
                    time.sleep(3)
                    
            except KeyboardInterrupt:
                print(f"\nTesting interrupted after {i+1} tests")
                break
            except Exception as e:
                print(f"Unexpected error in test {i+1}: {e}")
                continue
        
        # Save and summarize results
        self.save_results(all_results)
        self.print_summary(all_results)
    
    def print_summary(self, results: List[Dict]):
        """Print test summary"""
        print(f"\n{'='*60}")
        print("TEST SUMMARY")
        print(f"{'='*60}")
        
        successful = [r for r in results if r['status'] == 'completed']
        failed = [r for r in results if r['status'] == 'failed']
        
        print(f"Total Tests: {len(results)}")
        print(f"Successful: {len(successful)}")
        print(f"Failed: {len(failed)}")
        
        if successful:
            print(f"\nSUCCESSFUL TESTS:")
            for result in successful:
                scenario_name = result['scenario']['name']
                proc_results = result.get('processor_results', {})
                
                # Check for different metric structures based on processor type
                if proc_results.get('processor_type') == 'tppphase2':
                    # TPP Phase 2 structure - covert channel with metadata
                    file_size = proc_results.get('file_size_bytes', 0)
                    duration = proc_results.get('transmission_duration', 0)
                    capacity = proc_results.get('measured_capacity_bps', 0)
                    decryption = proc_results.get('decryption_used', False)
                    bits_used = proc_results.get('bits_to_use', 0)
                    print(f"  {scenario_name}: {file_size}B, {duration:.1f}s, {capacity:.1f}bps, {bits_used}bits, decrypt={decryption}")
                    
                elif 'performance_metrics' in proc_results:
                    # TPP Phase 4 structure
                    perf_metrics = proc_results['performance_metrics']
                    total_packets = perf_metrics.get('total_packets', 0)
                    suspicious_packets = perf_metrics.get('suspicious_packets', 0)
                    detection_rate = perf_metrics.get('detection_rate', 0)
                    mitigation_actions = perf_metrics.get('mitigation_actions', 0)
                    print(f"  {scenario_name}: Packets={total_packets}, Suspicious={suspicious_packets}, DetectionRate={detection_rate:.3f}, Mitigations={mitigation_actions}")
                    
                elif 'detection_metrics' in proc_results:
                    # TPP Phase 3 structure
                    metrics = proc_results['detection_metrics']
                    f1 = metrics.get('f1_score', 0)
                    accuracy = metrics.get('accuracy', 0)
                    print(f"  {scenario_name}: F1={f1:.3f}, Accuracy={accuracy:.3f}")
                    
                else:
                    # Try to extract basic info from any available metrics
                    runtime = proc_results.get('runtime_seconds', 0)
                    if runtime > 0:
                        print(f"  {scenario_name}: Runtime={runtime:.1f}s, Results available")
                    else:
                        print(f"  {scenario_name}: No metrics available")
        
        if failed:
            print(f"\nFAILED TESTS:")
            for result in failed:
                scenario_name = result['scenario']['name']
                error = result.get('error', 'Unknown error')
                print(f"  {scenario_name}: {error}")
    
    def test_docker_commands(self):
        """Test basic docker commands to debug issues"""
        print("Testing basic docker commands...")
        
        # Test basic connectivity
        print("\n1. Testing container connectivity:")
        containers = ["sec", "insec", "python-processor"]
        for container in containers:
            try:
                result = self.run_docker_command(container, "echo 'Hello from {}'".format(container))
                if result and result.returncode == 0:
                    print(f"  {container}: ✓ {result.stdout.strip()}")
                else:
                    print(f"  {container}: ✗ Error: {result.stderr if result else 'No response'}")
            except Exception as e:
                print(f"  {container}: ✗ Exception: {e}")
        
        # Test file system access
        print("\n2. Testing file system access:")
        try:
            result = self.run_docker_command("sec", "ls -la /code/sec/")
            if result and result.returncode == 0:
                print(f"  sec files: ✓")
                if "secret_message.txt" in result.stdout:
                    print(f"    secret_message.txt found ✓")
                else:
                    print(f"    secret_message.txt NOT found ✗")
            else:
                print(f"  sec files: ✗")
        except Exception as e:
            print(f"  sec files: ✗ Exception: {e}")
        
        # Test receiver directory
        try:
            result = self.run_docker_command("insec", "ls -la /code/insec/received_files/ 2>/dev/null || mkdir -p /code/insec/received_files && echo 'created directory'")
            if result:
                print(f"  insec received_files: ✓")
            else:
                print(f"  insec received_files: ✗")
        except Exception as e:
            print(f"  insec received_files: ✗ Exception: {e}")
        
        # Test a simple TPPhase2 command syntax
        print("\n3. Testing TPPhase2 command syntax:")
        try:
            result = self.run_docker_command("insec", "python3 /code/insec/tppphase2_receiver.py --help")
            if result and result.returncode == 0:
                print(f"  receiver help: ✓")
            else:
                print(f"  receiver help: ✗ {result.stderr if result else 'No response'}")
        except Exception as e:
            print(f"  receiver help: ✗ Exception: {e}")
        
        try:
            result = self.run_docker_command("sec", "python3 /code/sec/tppphase2_sender.py --help")
            if result and result.returncode == 0:
                print(f"  sender help: ✓")
            else:
                print(f"  sender help: ✗ {result.stderr if result else 'No response'}")
        except Exception as e:
            print(f"  sender help: ✗ Exception: {e}")
        
        print("\nDocker command test completed.")

def main():
    tester = TestRunner()
    tester.run_all_tests()

if __name__ == "__main__":
    main()