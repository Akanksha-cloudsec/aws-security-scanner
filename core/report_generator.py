"""Report Generator - Creates consolidated security reports"""

import json
import html
from pathlib import Path
from datetime import datetime
from jinja2 import Template
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self, results, output_dir):
        self.results = results
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def calculate_overall_score(self):
        """Calculate overall security score based on findings"""
        total_issues = 0
        max_possible_issues = 100  # Baseline
        
        # Count issues from different scanners
        if 's3' in self.results:
            total_issues += self.results['s3'].get('total_issues', 0)
        
        if 'iam' in self.results:
            total_issues += self.results['iam'].get('total_issues', 0)
        
        if 'cloudtrail' in self.results:
            total_issues += self.results['cloudtrail'].get('total_issues', 0)
        
        # Calculate score (lower issues = higher score)
        score = max(0, 100 - (total_issues * 2))
        return min(100, score)
    
    def generate_html_report(self):
        """Generate HTML report using Jinja2 template from templates/report_template.html"""
        template_file = Path(__file__).parent.parent / 'templates' / 'report_template.html'
        
        if template_file.exists():
            with open(template_file, 'r', encoding='utf-8') as f:
                template_str = f.read()
        else:
            logger.warning("templates/report_template.html not found, using default template.")
            template_str = "<html><body><h1>AWS Security Report</h1></body></html>"
        
        # Prepare data for template
        s3_findings = self.results.get('s3', {})
        iam_findings = self.results.get('iam', {})
        cloudtrail_findings = self.results.get('cloudtrail', {})
        prowler_findings = self.results.get('prowler', {})
        scoutsuite_findings = self.results.get('scoutsuite', {})
        
        # Calculate severity metrics
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0
        
        # IAM stats
        if iam_findings and isinstance(iam_findings, dict):
            users_without_mfa = iam_findings.get('statistics', {}).get('users_without_mfa', 0)
            critical_count += users_without_mfa
            for user in iam_findings.get('users', []):
                if user.get('has_privileged_access') and user.get('issues'):
                    high_count += 1
        
        # S3 stats
        if s3_findings and isinstance(s3_findings, dict):
            for bucket in s3_findings.get('buckets', []):
                if bucket.get('public_access'):
                    high_count += 1
                if not bucket.get('encrypted'):
                    medium_count += 1
        
        # CloudTrail stats
        if cloudtrail_findings and isinstance(cloudtrail_findings, dict):
            if not cloudtrail_findings.get('best_practices_check', {}).get('has_trails'):
                critical_count += 1
            if not cloudtrail_findings.get('best_practices_check', {}).get('multi_region', {}).get('has_multi_region'):
                medium_count += 1
            low_count += len(cloudtrail_findings.get('issues', []))
            
        # Prowler stats
        if prowler_findings and isinstance(prowler_findings, dict):
            critical_count += prowler_findings.get('critical', 0)
            high_count += prowler_findings.get('high', 0)
            medium_count += prowler_findings.get('medium', 0)
            low_count += prowler_findings.get('low', 0)
            
        # ScoutSuite stats
        if scoutsuite_findings and isinstance(scoutsuite_findings, dict):
            critical_count += len(scoutsuite_findings.get('critical_findings', []))
        
        # Collect recommendations
        all_recommendations = []
        
        if s3_findings.get('issues'):
            all_recommendations.append("Enforce S3 Block Public Access across all buckets and enable server-side encryption (KMS).")
        
        if iam_findings.get('issues'):
            users_without_mfa = iam_findings.get('statistics', {}).get('users_without_mfa', 0)
            if users_without_mfa > 0:
                all_recommendations.append(f"Enforce Multi-Factor Authentication (MFA) immediately for {users_without_mfa} IAM user account(s).")
            all_recommendations.append("Audit privileged IAM Administrator roles and apply the principle of least privilege.")
        
        if cloudtrail_findings.get('recommendations'):
            all_recommendations.extend(cloudtrail_findings['recommendations'])
        
        if not all_recommendations:
            all_recommendations.append("No immediate critical findings detected. Continue regular security monitoring and compliance reviews.")
        
        total_issues = critical_count + high_count + medium_count + low_count
        
        template = Template(template_str)
        html_content = template.render(
            timestamp=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            region=self.results.get('region', 'us-east-1'),
            overall_score=self.calculate_overall_score(),
            total_issues=total_issues,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            s3_findings=s3_findings,
            iam_findings=iam_findings,
            cloudtrail_findings=cloudtrail_findings,
            prowler_findings=prowler_findings,
            scoutsuite_findings=scoutsuite_findings,
            all_recommendations=all_recommendations
        )
        
        # Save HTML report
        html_file = self.output_dir / 'security_report.html'
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return html_file

    
    def generate_json_report(self):
        """Generate JSON report"""
        json_file = self.output_dir / 'security_report.json'
        
        report_data = {
            'timestamp': datetime.now().isoformat(),
            'overall_score': self.calculate_overall_score(),
            'scan_results': self.results,
            'summary': {
                'total_issues': sum(
                    r.get('total_issues', 0) for r in self.results.values()
                    if isinstance(r, dict)
                )
            }
        }
        
        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return json_file
    
    def generate_pdf_report(self):
        """Generate PDF report from the HTML template"""
        try:
            from xhtml2pdf import pisa
        except ImportError:
            logger.error("xhtml2pdf not installed. Run `pip install xhtml2pdf` to generate PDF reports.")
            return None
            
        pdf_file = self.output_dir / 'security_report.pdf'
        html_file = self.generate_html_report()
            
        with open(html_file, 'r', encoding='utf-8') as f:
            source_html = f.read()
            
        with open(pdf_file, "w+b") as result_file:
            pisa_status = pisa.CreatePDF(source_html, dest=result_file)
            
        if pisa_status.err:
            logger.error("PDF generation failed.")
            return None
            
        return pdf_file
    
    def generate_all_formats(self):
        """Generate all report formats"""
        logger.info("Generating reports...")
        
        reports = {}
        
        # Generate HTML report
        html_path = self.generate_html_report()
        reports['html'] = str(html_path)
        
        # Generate JSON report
        json_path = self.generate_json_report()
        reports['json'] = str(json_path)
        
        # Generate PDF report
        pdf_path = self.generate_pdf_report()
        if pdf_path:
            reports['pdf'] = str(pdf_path)
        
        logger.info(f"Reports generated: {reports}")
        
        return reports