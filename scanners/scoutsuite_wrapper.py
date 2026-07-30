import subprocess
import json
import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)

class ScoutSuiteWrapper:
    def __init__(self, session, output_dir):
        self.session = session
        self.output_dir = Path(output_dir) 
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        credentials = session.get_credentials()
        self.access_key = credentials.access_key
        self.secret_key = credentials.secret_key
    
    def run_scan(self):
       
        report_dir = self.output_dir 
        report_dir.mkdir(exist_ok=True)
        
        # Build ScoutSuite command
        cmd = [
            'scout', 'aws',
            '--access-keys',
            '--access-key-id', self.access_key,
            '--secret-access-key', self.secret_key,
            '--report-dir', str(report_dir),
            '--quiet'
        ]
        
        try:
            logger.info("Running ScoutSuite scan...")
            
            # Execute ScoutSuite
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode != 0:
                logger.error(f"ScoutSuite failed: {result.stderr}")
                return {'error': result.stderr}
            
            # Look for ScoutSuite results
            results_dir = report_dir / 'scoutsuite-results'
            results_file = next(results_dir.glob('scoutsuite_results_*.js'), None) if results_dir.exists() else None
            
            if results_file and results_file.exists():
                # Parse results (ScoutSuite outputs JS file with JSON)
                with open(results_file, 'r') as f:
                    content = f.read()
                    # Extract JSON from JS
                    json_start = content.find('{')
                    if json_start != -1:
                        json_content = content[json_start:]
                        scoutsuite_results = json.loads(json_content)
                        
                        findings = self.summarize_findings(scoutsuite_results)
                        findings['report_dir'] = str(report_dir)
                        return findings
            
            return {
                'status': 'completed',
                'report_dir': str(report_dir),
                'message': 'ScoutSuite scan completed'
            }
            
        except subprocess.TimeoutExpired:
            logger.error("ScoutSuite scan timed out")
            return {'error': 'Scan timed out after 1 hour'}
        except FileNotFoundError:
            logger.error("ScoutSuite not found. Please install: pip install scoutsuite")
            return {'error': 'ScoutSuite not installed'}
        except Exception as e:
            logger.error(f"ScoutSuite execution failed: {str(e)}")
            return {'error': str(e)}
    
    def summarize_findings(self, results):
        """Summarize ScoutSuite findings"""
        summary = {
            'total_issues': 0,
            'services_checked': [],
            'issues_by_severity': {},
            'critical_findings': []
        }
        
        # Navigate through ScoutSuite's complex output structure
        if 'services' in results:
            for service_name, service_data in results['services'].items():
                summary['services_checked'].append(service_name)
                
                if 'findings' in service_data:
                    for finding_type, finding_data in service_data['findings'].items():
                        if 'items' in finding_data:
                            for item_id, item_data in finding_data['items'].items():
                                severity = item_data.get('severity', 'unknown')
                                summary['total_issues'] += 1
                                summary['issues_by_severity'][severity] = summary['issues_by_severity'].get(severity, 0) + 1
                                
                                if severity == 'critical':
                                    summary['critical_findings'].append({
                                        'service': service_name,
                                        'finding': finding_type,
                                        'description': item_data.get('description', 'N/A')
                                    })
        
        return summary