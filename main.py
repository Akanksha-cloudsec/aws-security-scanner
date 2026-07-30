#!/usr/bin/env python3
"""
AWS Security Scanner - Main
Scans AWS account using multiple tools and generates report
"""

import os
import sys
import argparse
import json
import logging
import getpass
from datetime import datetime
from colorama import init, Fore, Style
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.aws_auth import create_aws_session, validate_credentials
from core.logger import setup_logger
from scanners.s3_scanner import S3Scanner
from scanners.iam_enum import IAMEnumerator
from scanners.cloudtrail_analyzer import CloudTrailAnalyzer
from scanners.scoutsuite_wrapper import ScoutSuiteWrapper
from core.report_generator import ReportGenerator

init(autoreset=True)

class AWSSecurityScanner:
    def __init__(self, access_key, secret_key, region='us-east-1', output_dir='./outputs'):
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.output_dir = Path(output_dir)
        self.session = None
        self.results = {'region': self.region}
        
        # Setup directories
        self.raw_dir = self.output_dir / 'raw'
        self.reports_dir = self.output_dir / 'reports'
        self.logs_dir = self.output_dir / 'logs'
        
        for dir_path in [self.raw_dir, self.reports_dir, self.logs_dir]:
            dir_path.mkdir(parents=True, exist_ok=True)
        
        # Setup logger
        self.logger = setup_logger('aws_scanner', self.logs_dir / 'scanner.log')
    
    def initialize_aws_session(self):
        """Initialize AWS session with provided credentials"""
        print(f"\n{Fore.CYAN}🔐 Initializing AWS session...{Style.RESET_ALL}")
        self.session = create_aws_session(self.access_key, self.secret_key, self.region)
        
        if validate_credentials(self.session):
            print(f"{Fore.GREEN}✅ AWS credentials validated successfully{Style.RESET_ALL}")
            self.logger.info("AWS session created successfully")
            return True
        else:
            print(f"{Fore.RED}❌ Invalid AWS credentials{Style.RESET_ALL}")
            self.logger.error("Invalid AWS credentials")
            return False
    
    def run_s3_scan(self):
        """Run S3 bucket scanner"""
        print(f"\n{Fore.CYAN}📦 Scanning S3 buckets...{Style.RESET_ALL}")
        try:
            scanner = S3Scanner(self.session)
            results = scanner.scan_all_buckets()
            self.results['s3'] = results
            
            # Save raw output
            output_file = self.raw_dir / 's3_scan.json'
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"{Fore.GREEN}✅ S3 scan completed. Found {len(results.get('buckets', []))} buckets{Style.RESET_ALL}")
            self.logger.info(f"S3 scan completed: {len(results.get('buckets', []))} buckets found")
        except Exception as e:
            print(f"{Fore.RED}❌ S3 scan failed: {str(e)}{Style.RESET_ALL}")
            self.logger.error(f"S3 scan failed: {str(e)}")
            self.results['s3'] = {'error': str(e)}
    
    def run_iam_scan(self):
        """Run IAM enumeration"""
        print(f"\n{Fore.CYAN}👥 Enumerating IAM resources...{Style.RESET_ALL}")
        try:
            enumerator = IAMEnumerator(self.session)
            results = enumerator.enumerate_all()
            self.results['iam'] = results
            
            # Save raw output
            output_file = self.raw_dir / 'iam_enum.json'
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"{Fore.GREEN}✅ IAM enumeration completed{Style.RESET_ALL}")
            self.logger.info("IAM enumeration completed")
        except Exception as e:
            print(f"{Fore.RED}❌ IAM enumeration failed: {str(e)}{Style.RESET_ALL}")
            self.logger.error(f"IAM enumeration failed: {str(e)}")
            self.results['iam'] = {'error': str(e)}
    
    def run_cloudtrail_scan(self):
        """Run CloudTrail analysis"""
        print(f"\n{Fore.CYAN}📊 Analyzing CloudTrail...{Style.RESET_ALL}")
        try:
            analyzer = CloudTrailAnalyzer(self.session)
            results = analyzer.analyze()
            self.results['cloudtrail'] = results
            
            # Save raw output
            output_file = self.raw_dir / 'cloudtrail_analysis.json'
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            
            print(f"{Fore.GREEN}✅ CloudTrail analysis completed{Style.RESET_ALL}")
            self.logger.info("CloudTrail analysis completed")
        except Exception as e:
            print(f"{Fore.RED}❌ CloudTrail analysis failed: {str(e)}{Style.RESET_ALL}")
            self.logger.error(f"CloudTrail analysis failed: {str(e)}")
            self.results['cloudtrail'] = {'error': str(e)}
    
    def run_scoutsuite_scan(self):
        """Run ScoutSuite scanner"""
        print(f"\n{Fore.CYAN}🔭 Running ScoutSuite scan...{Style.RESET_ALL}")
        try:
            wrapper = ScoutSuiteWrapper(self.session, self.raw_dir)
            results = wrapper.run_scan()
            self.results['scoutsuite'] = results
            print(f"{Fore.GREEN}✅ ScoutSuite scan completed{Style.RESET_ALL}")
            self.logger.info("ScoutSuite scan completed")
        except Exception as e:
            print(f"{Fore.RED}❌ ScoutSuite scan failed: {str(e)}{Style.RESET_ALL}")
            self.logger.error(f"ScoutSuite scan failed: {str(e)}")
            self.results['scoutsuite'] = {'error': str(e)}
    
    def generate_final_report(self):
        """Generate consolidated report"""
        print(f"\n{Fore.CYAN}📝 Generating final report...{Style.RESET_ALL}")
        try:
            report_gen = ReportGenerator(self.results, self.reports_dir)
            report_paths = report_gen.generate_all_formats()
            
            print(f"\n{Fore.GREEN}✅ Reports generated successfully:{Style.RESET_ALL}")
            for fmt, path in report_paths.items():
                print(f"  📄 {fmt.upper()}: {path}")
            
            self.logger.info(f"Reports generated: {report_paths}")
        except Exception as e:
            print(f"{Fore.RED}❌ Report generation failed: {str(e)}{Style.RESET_ALL}")
            self.logger.error(f"Report generation failed: {str(e)}")
    
    def run_full_scan(self):
        """Execute all scans in sequence"""
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}🚀 AWS Security Scanner - Starting Full Scan{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"Region: {self.region}")
        print(f"Output Directory: {self.output_dir}")
        print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        start_time = datetime.now()
        
        # Initialize AWS session
        if not self.initialize_aws_session():
            sys.exit(1)
        
        # Run all scans
        self.run_s3_scan()
        self.run_iam_scan()
        self.run_cloudtrail_scan()
        self.run_scoutsuite_scan()
        
        # Generate report
        self.generate_final_report()
        
        end_time = datetime.now()
        duration = end_time - start_time
        
        print(f"\n{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}✅ Scan completed successfully!{Style.RESET_ALL}")
        print(f"Duration: {duration.total_seconds():.2f} seconds")
        print(f"Reports saved in: {self.reports_dir}")
        print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='AWS Security Scanner')
    parser.add_argument('--access-key', help='AWS Access Key ID')
    parser.add_argument('--secret-key', help='AWS Secret Access Key')
    parser.add_argument('--region', default='us-east-1', help='AWS Region (default: us-east-1)')
    parser.add_argument('--output-dir', default='./outputs', help='Output directory (default: ./outputs)')
    
    args = parser.parse_args()
    
    # Get credentials from args or environment
    access_key = args.access_key or os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = args.secret_key or os.environ.get('AWS_SECRET_ACCESS_KEY')
    
    if not access_key or not secret_key:
        print(f"{Fore.YELLOW}⚠️ AWS credentials not found in environment or arguments.{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Please enter your credentials below:{Style.RESET_ALL}")
        access_key = input("AWS_ACCESS_KEY_ID: ").strip()
        secret_key = input("AWS_SECRET_ACCESS_KEY: ").strip()
        
        if not access_key or not secret_key:
            print(f"{Fore.RED}❌ Error: AWS credentials are required to run the scanner.{Style.RESET_ALL}")
            sys.exit(1)
    
    # Run scanner
    scanner = AWSSecurityScanner(access_key, secret_key,args.region,  args.output_dir)   
    scanner.run_full_scan()

if __name__ == '__main__': 
    main()