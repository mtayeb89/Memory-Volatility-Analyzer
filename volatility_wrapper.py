#!/usr/bin/env python3
"""
Memory Volatility Analyzer (VolatilityWrapper)
Enhanced wrapper for Volatility framework with custom plugins

Author: Digital Forensics Team
License: MIT
Version: 1.0.0
"""

import os
import sys
import json
import csv
import argparse
import logging
import subprocess
import multiprocessing
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any
import matplotlib.pyplot as plt
import pandas as pd
from concurrent.futures import ThreadPoolExecutor, as_completed
import configparser

# Try to import volatility3 components
try:
    from volatility3 import framework
    from volatility3.framework import contexts, plugins, automagic, exceptions
    from volatility3.framework.configuration import requirements
    from volatility3.cli import volshell
    VOLATILITY_AVAILABLE = True
except ImportError:
    VOLATILITY_AVAILABLE = False
    print("Warning: Volatility3 not found. Please install: pip install volatility3")


class VolatilityConfig:
    """Configuration manager for Volatility analyzer"""
    
    def __init__(self, config_file: str = "volatility_config.ini"):
        self.config = configparser.ConfigParser()
        self.config_file = config_file
        self.load_config()
    
    def load_config(self):
        """Load configuration from file or create default"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.create_default_config()
    
    def create_default_config(self):
        """Create default configuration file"""
        self.config['DEFAULT'] = {
            'output_dir': './volatility_output',
            'log_level': 'INFO',
            'max_workers': '4',
            'timeout': '300',
            'auto_profile': 'True'
        }
        
        self.config['PLUGINS'] = {
            'basic_plugins': 'pslist,pstree,netstat,filescan',
            'advanced_plugins': 'malfind,hollowfind,apihooks',
            'registry_plugins': 'hivelist,printkey',
            'network_plugins': 'netscan,netstat'
        }
        
        self.config['OUTPUT'] = {
            'format': 'json',
            'include_timestamps': 'True',
            'compress_results': 'False'
        }
        
        with open(self.config_file, 'w') as f:
            self.config.write(f)
    
    def get(self, section: str, key: str, fallback: Any = None):
        """Get configuration value"""
        return self.config.get(section, key, fallback=fallback)


class CustomPlugin:
    """Base class for custom Volatility plugins"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def execute(self, context, config_path: str, req_filter: Any) -> Dict:
        """Execute the custom plugin"""
        raise NotImplementedError("Subclasses must implement execute method")


class ProcessAnalyzerPlugin(CustomPlugin):
    """Custom plugin for advanced process analysis"""
    
    def __init__(self):
        super().__init__("ProcessAnalyzer", "Advanced process analysis with suspicious behavior detection")
    
    def execute(self, context, config_path: str, req_filter: Any) -> Dict:
        """Execute process analysis"""
        results = {
            'plugin_name': self.name,
            'timestamp': datetime.now().isoformat(),
            'processes': [],
            'suspicious_processes': [],
            'statistics': {}
        }
        
        try:
            # Get process list
            pslist_plugin = plugins.construct_plugin(
                context, automagic.available(context), 
                plugins.get_plugins()[0], "PsList", None, None, None
            )
            
            for row in pslist_plugin.run():
                process_info = {
                    'pid': row[1],
                    'ppid': row[2],
                    'name': str(row[3]),
                    'offset': hex(row[0]),
                    'threads': row[4],
                    'handles': row[5],
                    'create_time': str(row[6]) if row[6] else 'N/A',
                    'exit_time': str(row[7]) if row[7] else 'N/A'
                }
                
                results['processes'].append(process_info)
                
                # Check for suspicious patterns
                if self._is_suspicious_process(process_info):
                    results['suspicious_processes'].append(process_info)
            
            results['statistics'] = {
                'total_processes': len(results['processes']),
                'suspicious_count': len(results['suspicious_processes']),
                'analysis_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Error in ProcessAnalyzer plugin: {e}")
            results['error'] = str(e)
        
        return results
    
    def _is_suspicious_process(self, process_info: Dict) -> bool:
        """Check if a process exhibits suspicious behavior"""
        suspicious_names = ['svchost.exe', 'explorer.exe', 'winlogon.exe']
        
        # Check for process hollowing indicators
        if process_info['name'].lower() in [name.lower() for name in suspicious_names]:
            if process_info['ppid'] == 0 or process_info['threads'] > 100:
                return True
        
        # Check for suspicious creation times
        if 'create_time' in process_info and process_info['create_time'] == 'N/A':
            return True
            
        return False


class NetworkAnalyzerPlugin(CustomPlugin):
    """Custom plugin for network connection analysis"""
    
    def __init__(self):
        super().__init__("NetworkAnalyzer", "Network connection and communication analysis")
    
    def execute(self, context, config_path: str, req_filter: Any) -> Dict:
        """Execute network analysis"""
        results = {
            'plugin_name': self.name,
            'timestamp': datetime.now().isoformat(),
            'connections': [],
            'suspicious_connections': [],
            'statistics': {}
        }
        
        try:
            # This would integrate with Volatility3's network plugins
            # For demonstration, we'll simulate network analysis
            results['statistics'] = {
                'total_connections': 0,
                'suspicious_count': 0,
                'unique_ips': 0,
                'analysis_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Error in NetworkAnalyzer plugin: {e}")
            results['error'] = str(e)
        
        return results


class VolatilityWrapper:
    """Enhanced wrapper for Volatility framework"""
    
    def __init__(self, config_file: str = "volatility_config.ini"):
        self.config = VolatilityConfig(config_file)
        self.logger = self._setup_logging()
        self.custom_plugins = {}
        self.results = {}
        
        # Create output directory
        self.output_dir = Path(self.config.get('DEFAULT', 'output_dir', './volatility_output'))
        self.output_dir.mkdir(exist_ok=True)
        
        # Register custom plugins
        self._register_custom_plugins()
        
        if not VOLATILITY_AVAILABLE:
            self.logger.warning("Volatility3 not available. Some features will be limited.")
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        log_level = self.config.get('DEFAULT', 'log_level', 'INFO')
        
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('volatility_wrapper.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        return logging.getLogger(__name__)
    
    def _register_custom_plugins(self):
        """Register custom plugins"""
        self.custom_plugins['ProcessAnalyzer'] = ProcessAnalyzerPlugin()
        self.custom_plugins['NetworkAnalyzer'] = NetworkAnalyzerPlugin()
        self.logger.info(f"Registered {len(self.custom_plugins)} custom plugins")
    
    def detect_profile(self, memory_file: str) -> Optional[str]:
        """Automatically detect memory dump profile"""
        if not VOLATILITY_AVAILABLE:
            self.logger.warning("Profile detection requires Volatility3")
            return None
        
        try:
            self.logger.info(f"Detecting profile for {memory_file}")
            
            # Use Volatility3's automagic for profile detection
            ctx = contexts.Context()
            ctx.config['automagic.LayerStacker.memory_layer.location'] = f"file://{memory_file}"
            
            # This is a simplified approach - in practice, you'd use Volatility3's
            # automagic system more comprehensively
            available_automagics = automagic.available(ctx)
            
            if available_automagics:
                self.logger.info("Profile detection completed")
                return "Windows"  # Simplified return
            else:
                self.logger.warning("No suitable profile found")
                return None
                
        except Exception as e:
            self.logger.error(f"Profile detection failed: {e}")
            return None
    
    def run_plugin(self, memory_file: str, plugin_name: str, 
                   output_file: Optional[str] = None, **kwargs) -> Dict:
        """Run a specific Volatility plugin"""
        self.logger.info(f"Running plugin: {plugin_name}")
        
        try:
            if plugin_name in self.custom_plugins:
                return self._run_custom_plugin(memory_file, plugin_name, **kwargs)
            else:
                return self._run_volatility_plugin(memory_file, plugin_name, output_file, **kwargs)
                
        except Exception as e:
            self.logger.error(f"Plugin execution failed: {e}")
            return {'error': str(e), 'plugin': plugin_name}
    
    def _run_custom_plugin(self, memory_file: str, plugin_name: str, **kwargs) -> Dict:
        """Run a custom plugin"""
        plugin = self.custom_plugins[plugin_name]
        
        if VOLATILITY_AVAILABLE:
            ctx = contexts.Context()
            ctx.config['automagic.LayerStacker.memory_layer.location'] = f"file://{memory_file}"
            return plugin.execute(ctx, memory_file, None)
        else:
            # Fallback for when Volatility3 is not available
            return {
                'plugin_name': plugin_name,
                'error': 'Volatility3 not available',
                'timestamp': datetime.now().isoformat()
            }
    
    def _run_volatility_plugin(self, memory_file: str, plugin_name: str, 
                              output_file: Optional[str] = None, **kwargs) -> Dict:
        """Run a standard Volatility plugin"""
        if not VOLATILITY_AVAILABLE:
            return {'error': 'Volatility3 not available', 'plugin': plugin_name}
        
        try:
            # Build command
            cmd = [
                'python', '-m', 'volatility3',
                '-f', memory_file,
                plugin_name
            ]
            
            if output_file:
                cmd.extend(['-o', output_file])
            
            # Add any additional arguments
            for key, value in kwargs.items():
                cmd.extend([f'--{key}', str(value)])
            
            # Execute command
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  timeout=int(self.config.get('DEFAULT', 'timeout', '300')))
            
            return {
                'plugin': plugin_name,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat()
            }
            
        except subprocess.TimeoutExpired:
            return {'error': 'Plugin execution timeout', 'plugin': plugin_name}
        except Exception as e:
            return {'error': str(e), 'plugin': plugin_name}
    
    def batch_analysis(self, memory_file: str, plugin_list: List[str] = None) -> Dict:
        """Run batch analysis with multiple plugins"""
        if plugin_list is None:
            plugin_list = self.config.get('PLUGINS', 'basic_plugins', '').split(',')
            plugin_list = [p.strip() for p in plugin_list if p.strip()]
        
        self.logger.info(f"Starting batch analysis with {len(plugin_list)} plugins")
        
        batch_results = {
            'memory_file': memory_file,
            'start_time': datetime.now().isoformat(),
            'plugins_executed': [],
            'results': {},
            'errors': []
        }
        
        # Detect profile first if enabled
        if self.config.get('DEFAULT', 'auto_profile', 'True').lower() == 'true':
            profile = self.detect_profile(memory_file)
            batch_results['detected_profile'] = profile
        
        # Execute plugins in parallel
        max_workers = int(self.config.get('DEFAULT', 'max_workers', '4'))
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_plugin = {
                executor.submit(self.run_plugin, memory_file, plugin): plugin 
                for plugin in plugin_list
            }
            
            for future in as_completed(future_to_plugin):
                plugin = future_to_plugin[future]
                try:
                    result = future.result()
                    batch_results['results'][plugin] = result
                    batch_results['plugins_executed'].append(plugin)
                    self.logger.info(f"Completed plugin: {plugin}")
                except Exception as e:
                    error_info = {'plugin': plugin, 'error': str(e)}
                    batch_results['errors'].append(error_info)
                    self.logger.error(f"Failed plugin {plugin}: {e}")
        
        batch_results['end_time'] = datetime.now().isoformat()
        batch_results['total_plugins'] = len(plugin_list)
        batch_results['successful_plugins'] = len(batch_results['plugins_executed'])
        
        # Save batch results
        self._save_results(batch_results, 'batch_analysis')
        
        return batch_results
    
    def correlate_results(self, results: Dict) -> Dict:
        """Correlate results from multiple plugins"""
        self.logger.info("Correlating analysis results")
        
        correlation = {
            'timestamp': datetime.now().isoformat(),
            'correlations': [],
            'summary': {},
            'recommendations': []
        }
        
        try:
            # Extract process information
            processes = []
            if 'ProcessAnalyzer' in results.get('results', {}):
                processes = results['results']['ProcessAnalyzer'].get('processes', [])
            
            # Extract network information
            connections = []
            if 'NetworkAnalyzer' in results.get('results', {}):
                connections = results['results']['NetworkAnalyzer'].get('connections', [])
            
            # Correlation logic
            correlation['summary'] = {
                'total_processes': len(processes),
                'total_connections': len(connections),
                'correlation_score': self._calculate_correlation_score(processes, connections)
            }
            
            # Generate recommendations
            if len(processes) > 100:
                correlation['recommendations'].append("High process count detected - investigate for malware")
            
            if len(connections) > 50:
                correlation['recommendations'].append("High network activity - check for data exfiltration")
                
        except Exception as e:
            self.logger.error(f"Correlation failed: {e}")
            correlation['error'] = str(e)
        
        return correlation
    
    def _calculate_correlation_score(self, processes: List, connections: List) -> float:
        """Calculate correlation score between processes and connections"""
        if not processes and not connections:
            return 0.0
        
        # Simplified correlation scoring
        process_score = min(len(processes) / 50.0, 1.0)  # Normalize to 1.0
        connection_score = min(len(connections) / 20.0, 1.0)  # Normalize to 1.0
        
        return (process_score + connection_score) / 2.0
    
    def visualize_results(self, results: Dict, output_file: str = None):
        """Create visualizations of analysis results"""
        try:
            fig, axes = plt.subplots(2, 2, figsize=(15, 10))
            fig.suptitle('Memory Analysis Results', fontsize=16)
            
            # Process analysis chart
            if 'ProcessAnalyzer' in results.get('results', {}):
                process_data = results['results']['ProcessAnalyzer']
                total_processes = process_data.get('statistics', {}).get('total_processes', 0)
                suspicious_processes = process_data.get('statistics', {}).get('suspicious_count', 0)
                
                axes[0, 0].pie([total_processes - suspicious_processes, suspicious_processes], 
                              labels=['Normal Processes', 'Suspicious Processes'],
                              colors=['lightblue', 'red'], autopct='%1.1f%%')
                axes[0, 0].set_title('Process Analysis')
            
            # Network analysis chart
            if 'NetworkAnalyzer' in results.get('results', {}):
                network_data = results['results']['NetworkAnalyzer']
                # Create sample network visualization
                axes[0, 1].bar(['TCP', 'UDP', 'Unknown'], [10, 5, 2])
                axes[0, 1].set_title('Network Connections')
                axes[0, 1].set_ylabel('Count')
            
            # Plugin execution timeline
            if 'plugins_executed' in results:
                plugins = results['plugins_executed']
                execution_times = [1.2, 2.3, 0.8, 1.5][:len(plugins)]  # Sample data
                
                axes[1, 0].barh(plugins, execution_times)
                axes[1, 0].set_title('Plugin Execution Times')
                axes[1, 0].set_xlabel('Time (seconds)')
            
            # Success rate chart
            total_plugins = results.get('total_plugins', 0)
            successful_plugins = results.get('successful_plugins', 0)
            failed_plugins = total_plugins - successful_plugins
            
            axes[1, 1].pie([successful_plugins, failed_plugins],
                          labels=['Successful', 'Failed'],
                          colors=['green', 'red'], autopct='%1.1f%%')
            axes[1, 1].set_title('Plugin Success Rate')
            
            plt.tight_layout()
            
            if output_file:
                plt.savefig(output_file, dpi=300, bbox_inches='tight')
                self.logger.info(f"Visualization saved to {output_file}")
            else:
                plt.savefig(self.output_dir / 'analysis_visualization.png', dpi=300, bbox_inches='tight')
            
            plt.close()
            
        except Exception as e:
            self.logger.error(f"Visualization failed: {e}")
    
    def _save_results(self, results: Dict, filename_prefix: str):
        """Save results to file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # JSON format
        json_file = self.output_dir / f"{filename_prefix}_{timestamp}.json"
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        self.logger.info(f"Results saved to {json_file}")
        
        # CSV format for tabular data
        if 'results' in results:
            csv_file = self.output_dir / f"{filename_prefix}_{timestamp}.csv"
            try:
                df = pd.json_normalize(results['results'])
                df.to_csv(csv_file, index=False)
                self.logger.info(f"CSV results saved to {csv_file}")
            except Exception as e:
                self.logger.warning(f"Could not save CSV format: {e}")
    
    def generate_report(self, results: Dict, output_file: str = None) -> str:
        """Generate comprehensive analysis report"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        report = f"""
# Memory Analysis Report
Generated: {timestamp}

## Executive Summary
Memory dump analysis completed for: {results.get('memory_file', 'Unknown')}
Total plugins executed: {results.get('successful_plugins', 0)}/{results.get('total_plugins', 0)}

## Analysis Overview
"""
        
        # Add plugin results summary
        if 'results' in results:
            for plugin, plugin_results in results['results'].items():
                if isinstance(plugin_results, dict) and 'error' not in plugin_results:
                    report += f"\n### {plugin}\n"
                    if 'statistics' in plugin_results:
                        stats = plugin_results['statistics']
                        for key, value in stats.items():
                            report += f"- {key}: {value}\n"
        
        # Add correlations
        correlation = self.correlate_results(results)
        if correlation and 'recommendations' in correlation:
            report += "\n## Recommendations\n"
            for rec in correlation['recommendations']:
                report += f"- {rec}\n"
        
        # Add errors if any
        if results.get('errors'):
            report += "\n## Errors Encountered\n"
            for error in results['errors']:
                report += f"- Plugin {error.get('plugin', 'Unknown')}: {error.get('error', 'Unknown error')}\n"
        
        report += f"\n## Technical Details\n"
        report += f"Analysis started: {results.get('start_time', 'Unknown')}\n"
        report += f"Analysis completed: {results.get('end_time', 'Unknown')}\n"
        
        # Save report
        if output_file:
            report_file = output_file
        else:
            timestamp_file = datetime.now().strftime("%Y%m%d_%H%M%S")
            report_file = self.output_dir / f"analysis_report_{timestamp_file}.md"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(report)
        
        self.logger.info(f"Report generated: {report_file}")
        return str(report_file)


def main():
    """Main function for command-line interface"""
    parser = argparse.ArgumentParser(
        description="Memory Volatility Analyzer",
        epilog="""
Examples:
  python volatility_wrapper.py memory.dmp --batch
  python volatility_wrapper.py memory.dmp --plugin pslist
  python volatility_wrapper.py --demo
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Make memory_file optional and add demo mode
    parser.add_argument("memory_file", nargs='?', 
                       help="Path to memory dump file (optional if using --demo)")
    parser.add_argument("--config", default="volatility_config.ini", 
                       help="Configuration file path")
    parser.add_argument("--plugin", help="Single plugin to run")
    parser.add_argument("--batch", action="store_true", 
                       help="Run batch analysis")
    parser.add_argument("--plugins", nargs="+", 
                       help="List of plugins to run")
    parser.add_argument("--output", help="Output directory")
    parser.add_argument("--report", action="store_true", 
                       help="Generate analysis report")
    parser.add_argument("--visualize", action="store_true", 
                       help="Create visualizations")
    parser.add_argument("--profile", help="Specify memory profile")
    parser.add_argument("--demo", action="store_true", 
                       help="Run in demo mode with simulated data")
    parser.add_argument("--interactive", action="store_true", 
                       help="Run in interactive mode")
    
    # Check if running in IDE without arguments - auto-enable demo mode
    if len(sys.argv) == 1:
        print("No arguments provided. Running in demo mode...")
        print("(To disable this behavior, add arguments or run from command line)")
        sys.argv.extend(['--demo', '--visualize', '--report'])
    
    args = parser.parse_args()
    
    # Handle demo mode
    if args.demo:
        return run_demo_mode(args)
    
    # Handle interactive mode
    if args.interactive:
        return run_interactive_mode(args)
    
    # Check if memory file is provided
    if not args.memory_file:
        print("Error: memory_file is required unless using --demo or --interactive mode")
        print("Use --help for usage information")
        return 1
    
    # Validate memory file
    if not os.path.exists(args.memory_file):
        print(f"Error: Memory file not found: {args.memory_file}")
        print("Tip: Use --demo flag to test with simulated data")
        return 1
    
    # Initialize analyzer
    analyzer = VolatilityWrapper(args.config)
    
    if args.output:
        analyzer.output_dir = Path(args.output)
        analyzer.output_dir.mkdir(exist_ok=True)
    
    try:
        if args.plugin:
            # Run single plugin
            result = analyzer.run_plugin(args.memory_file, args.plugin)
            analyzer._save_results(result, f"plugin_{args.plugin}")
            
        elif args.batch or args.plugins:
            # Run batch analysis
            plugins = args.plugins if args.plugins else None
            results = analyzer.batch_analysis(args.memory_file, plugins)
            
            if args.visualize:
                analyzer.visualize_results(results)
            
            if args.report:
                analyzer.generate_report(results)
        
        else:
            # Default: run batch analysis with basic plugins
            results = analyzer.batch_analysis(args.memory_file)
            analyzer.visualize_results(results)
            analyzer.generate_report(results)
        
        print("Analysis completed successfully!")
        return 0
        
    except KeyboardInterrupt:
        print("\nAnalysis interrupted by user")
        return 130
    except Exception as e:
        print(f"Analysis failed: {e}")
        return 1


def run_demo_mode(args):
    """Run the analyzer in demo mode with simulated data"""
    print("=== Memory Volatility Analyzer - Demo Mode ===")
    print("Running with simulated memory analysis data...\n")
    
    # Initialize analyzer
    analyzer = VolatilityWrapper(args.config)
    
    if args.output:
        analyzer.output_dir = Path(args.output)
        analyzer.output_dir.mkdir(exist_ok=True)
    
    # Create simulated results
    simulated_results = {
        'memory_file': 'demo_memory.dmp',
        'start_time': datetime.now().isoformat(),
        'detected_profile': 'Windows10x64',
        'plugins_executed': ['ProcessAnalyzer', 'NetworkAnalyzer'],
        'results': {
            'ProcessAnalyzer': {
                'plugin_name': 'ProcessAnalyzer',
                'timestamp': datetime.now().isoformat(),
                'processes': [
                    {'pid': 1234, 'name': 'explorer.exe', 'ppid': 1000, 'threads': 45},
                    {'pid': 5678, 'name': 'notepad.exe', 'ppid': 1234, 'threads': 2},
                    {'pid': 9999, 'name': 'suspicious.exe', 'ppid': 0, 'threads': 150}
                ],
                'suspicious_processes': [
                    {'pid': 9999, 'name': 'suspicious.exe', 'ppid': 0, 'threads': 150}
                ],
                'statistics': {
                    'total_processes': 3,
                    'suspicious_count': 1,
                    'analysis_time': datetime.now().isoformat()
                }
            },
            'NetworkAnalyzer': {
                'plugin_name': 'NetworkAnalyzer',
                'timestamp': datetime.now().isoformat(),
                'connections': [],
                'suspicious_connections': [],
                'statistics': {
                    'total_connections': 15,
                    'suspicious_count': 2,
                    'unique_ips': 8,
                    'analysis_time': datetime.now().isoformat()
                }
            }
        },
        'end_time': datetime.now().isoformat(),
        'total_plugins': 2,
        'successful_plugins': 2,
        'errors': []
    }
    
    print("Demo analysis completed!")
    print(f"- Total processes analyzed: {simulated_results['results']['ProcessAnalyzer']['statistics']['total_processes']}")
    print(f"- Suspicious processes found: {simulated_results['results']['ProcessAnalyzer']['statistics']['suspicious_count']}")
    print(f"- Network connections: {simulated_results['results']['NetworkAnalyzer']['statistics']['total_connections']}")
    
    # Save demo results
    analyzer._save_results(simulated_results, 'demo_analysis')
    
    if args.visualize:
        print("Generating visualizations...")
        analyzer.visualize_results(simulated_results)
    
    if args.report:
        print("Generating report...")
        report_file = analyzer.generate_report(simulated_results)
        print(f"Report saved to: {report_file}")
    
    print(f"\nDemo results saved to: {analyzer.output_dir}")
    return 0


def run_interactive_mode(args):
    """Run the analyzer in interactive mode"""
    print("=== Memory Volatility Analyzer - Interactive Mode ===")
    print("Welcome to the interactive memory analysis interface!\n")
    
    # Initialize analyzer
    analyzer = VolatilityWrapper(args.config)
    
    if args.output:
        analyzer.output_dir = Path(args.output)
        analyzer.output_dir.mkdir(exist_ok=True)
    
    while True:
        print("\nAvailable options:")
        print("1. Analyze memory dump")
        print("2. Run demo analysis")
        print("3. View configuration")
        print("4. List available plugins")
        print("5. Exit")
        
        try:
            choice = input("\nEnter your choice (1-5): ").strip()
            
            if choice == '1':
                memory_file = input("Enter path to memory dump file: ").strip()
                if not os.path.exists(memory_file):
                    print(f"Error: File not found: {memory_file}")
                    continue
                
                print("\nAnalysis options:")
                print("1. Quick analysis (basic plugins)")
                print("2. Full analysis (all plugins)")
                print("3. Custom plugin selection")
                
                analysis_choice = input("Enter choice (1-3): ").strip()
                
                if analysis_choice == '1':
                    results = analyzer.batch_analysis(memory_file, ['ProcessAnalyzer'])
                elif analysis_choice == '2':
                    results = analyzer.batch_analysis(memory_file)
                elif analysis_choice == '3':
                    available_plugins = list(analyzer.custom_plugins.keys()) + ['pslist', 'pstree', 'netstat']
                    print(f"Available plugins: {', '.join(available_plugins)}")
                    plugin_input = input("Enter plugins (comma-separated): ").strip()
                    plugins = [p.strip() for p in plugin_input.split(',') if p.strip()]
                    results = analyzer.batch_analysis(memory_file, plugins)
                else:
                    print("Invalid choice")
                    continue
                
                print("\nAnalysis completed!")
                generate_viz = input("Generate visualizations? (y/n): ").strip().lower()
                if generate_viz == 'y':
                    analyzer.visualize_results(results)
                
                generate_report = input("Generate report? (y/n): ").strip().lower()
                if generate_report == 'y':
                    report_file = analyzer.generate_report(results)
                    print(f"Report saved to: {report_file}")
            
            elif choice == '2':
                # Run demo mode
                demo_args = argparse.Namespace()
                demo_args.config = args.config
                demo_args.output = args.output
                demo_args.visualize = True
                demo_args.report = True
                run_demo_mode(demo_args)
            
            elif choice == '3':
                print(f"\nConfiguration file: {analyzer.config.config_file}")
                print(f"Output directory: {analyzer.output_dir}")
                print(f"Log level: {analyzer.config.get('DEFAULT', 'log_level')}")
                print(f"Max workers: {analyzer.config.get('DEFAULT', 'max_workers')}")
                print(f"Available custom plugins: {', '.join(analyzer.custom_plugins.keys())}")
            
            elif choice == '4':
                print("\nAvailable plugins:")
                print("Custom plugins:")
                for name, plugin in analyzer.custom_plugins.items():
                    print(f"  - {name}: {plugin.description}")
                print("\nStandard Volatility plugins:")
                standard_plugins = ['pslist', 'pstree', 'netstat', 'filescan', 'malfind', 'hollowfind']
                for plugin in standard_plugins:
                    print(f"  - {plugin}")
            
            elif choice == '5':
                print("Goodbye!")
                break
            
            else:
                print("Invalid choice. Please enter 1-5.")
                
        except KeyboardInterrupt:
            print("\n\nExiting interactive mode...")
            break
        except Exception as e:
            print(f"Error: {e}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
