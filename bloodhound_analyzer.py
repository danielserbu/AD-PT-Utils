#!/usr/bin/env python3
import argparse
import json
import os
import sys
import time
import re
import logging
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("bloodhound_analyzer.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("bloodhound_analyzer")

class BloodHoundAnalyzer:
    """Analyze BloodHound data to identify attack paths and create reports"""
    
    def __init__(self, uri: str, username: str, password: str, output_dir: str = None):
        """Initialize BloodHound analyzer with Neo4j connection details"""
        self.uri = uri
        self.username = username
        self.password = password
        self.driver = None
        self.connected = False
        
        # Set output directory
        self.output_dir = Path(output_dir) if output_dir else Path("bloodhound_reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        # Store results for reporting
        self.domain_info = {}
        self.high_value_targets = []
        self.kerberoastable_users = []
        self.asreproastable_users = []
        self.admin_users = []
        self.users_with_path_to_da = []
        self.gpo_impacts = []
        self.computers_with_admin_local = []
        self.critical_attack_paths = []
        self.domain_trusts = []
        self.dcsync_rights = []
        self.owned_objects = []
        self.certificate_vulnerabilities = []
        
        # Connect to Neo4j
        self.connect()
    
    def connect(self) -> bool:
        """Connect to Neo4j database"""
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.username, self.password))
            self.driver.verify_connectivity()
            self.connected = True
            logger.info(f"Successfully connected to Neo4j at {self.uri}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to Neo4j: {str(e)}")
            self.connected = False
            return False
    
    def close(self):
        """Close Neo4j connection"""
        if self.driver:
            self.driver.close()
            logger.info("Neo4j connection closed")
    
    def _run_query(self, query: str, params: Dict = None) -> List[Dict]:
        """Run a Cypher query and return results"""
        if not self.connected:
            logger.error("Not connected to Neo4j")
            return []
        
        try:
            with self.driver.session() as session:
                result = session.run(query, params or {})
                return [record.data() for record in result]
        except Exception as e:
            logger.error(f"Error running query: {str(e)}")
            logger.error(f"Query: {query}")
            return []
    
    def get_domain_info(self) -> Dict[str, Any]:
        """Get basic information about domain(s)"""
        logger.info("Getting domain information")
        
        query = """
        MATCH (d:Domain)
        RETURN d.name as domain, d.functionallevel as functional_level
        """
        
        domains = self._run_query(query)
        
        if domains:
            self.domain_info["domains"] = domains
            logger.info(f"Found {len(domains)} domains")
            
            # Get domain users count
            users_query = """
            MATCH (d:Domain)
            OPTIONAL MATCH (u:User)-[:MemberOf*1..]->(:Group)-[:MemberOf]->(d)
            RETURN d.name as domain, count(DISTINCT u) as user_count
            """
            
            user_counts = self._run_query(users_query)
            self.domain_info["user_counts"] = user_counts
            
            # Get domain computer count
            computers_query = """
            MATCH (d:Domain)
            OPTIONAL MATCH (c:Computer)-[:MemberOf*1..]->(:Group)-[:MemberOf]->(d)
            RETURN d.name as domain, count(DISTINCT c) as computer_count
            """
            
            computer_counts = self._run_query(computers_query)
            self.domain_info["computer_counts"] = computer_counts
            
            # Get domain controllers
            dc_query = """
            MATCH (c:Computer {domain: $domain})
            WHERE c.objectid CONTAINS "S-1-5-21" AND c.objectid ENDS WITH "1000"
            RETURN c.name as name, c.operatingsystem as os
            """
            
            dcs = {}
            for domain in domains:
                domain_name = domain["domain"]
                domain_dcs = self._run_query(dc_query, {"domain": domain_name})
                dcs[domain_name] = domain_dcs
            
            self.domain_info["domain_controllers"] = dcs
        
        return self.domain_info
    
    def find_high_value_targets(self) -> List[Dict[str, Any]]:
        """Find high value targets in the domain"""
        logger.info("Finding high value targets")
        
        # High value targets are: Domain Controllers, Domain Admins, Enterprise Admins, Administrators
        query = """
        MATCH (c:Computer)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH "-516" OR c.objectid ENDS WITH "1000"
        RETURN DISTINCT c.name as name, c.operatingsystem as os, 'Domain Controller' as type
        UNION
        MATCH (u:User)-[:MemberOf*1..]->(g:Group)
        WHERE g.objectid ENDS WITH "-512" OR g.objectid ENDS WITH "-519" OR g.objectid ENDS WITH "-500"
        RETURN DISTINCT u.name as name, labels(u) as os, 
               CASE 
                  WHEN g.objectid ENDS WITH "-512" THEN 'Domain Admin' 
                  WHEN g.objectid ENDS WITH "-519" THEN 'Enterprise Admin'
                  WHEN g.objectid ENDS WITH "-500" THEN 'Administrator'
               END as type
        """
        
        high_value_targets = self._run_query(query)
        self.high_value_targets = high_value_targets
        
        logger.info(f"Found {len(high_value_targets)} high value targets")
        return high_value_targets
    
    def find_kerberoastable_users(self) -> List[Dict[str, Any]]:
        """Find Kerberoastable users"""
        logger.info("Finding Kerberoastable users")
        
        query = """
        MATCH (u:User)
        WHERE u.hasspn=true
        RETURN u.name as name, u.displayname as display_name, u.enabled as enabled
        """
        
        kerberoastable = self._run_query(query)
        self.kerberoastable_users = kerberoastable
        
        logger.info(f"Found {len(kerberoastable)} Kerberoastable users")
        return kerberoastable
    
    def find_asreproastable_users(self) -> List[Dict[str, Any]]:
        """Find AS-REP Roastable users (users with DONT_REQ_PREAUTH)"""
        logger.info("Finding AS-REP Roastable users")
        
        query = """
        MATCH (u:User)
        WHERE u.dontreqpreauth=true
        RETURN u.name as name, u.displayname as display_name, u.enabled as enabled
        """
        
        asreproastable = self._run_query(query)
        self.asreproastable_users = asreproastable
        
        logger.info(f"Found {len(asreproastable)} AS-REP Roastable users")
        return asreproastable
    
    def find_admin_users(self) -> List[Dict[str, Any]]:
        """Find users with adminCount=1"""
        logger.info("Finding users with adminCount=1")
        
        query = """
        MATCH (u:User {admincount: true})
        RETURN u.name as name, u.displayname as display_name, u.enabled as enabled,
               [(u)-[:MemberOf*1..]->(g:Group) | g.name] as group_memberships
        """
        
        admin_users = self._run_query(query)
        self.admin_users = admin_users
        
        logger.info(f"Found {len(admin_users)} users with adminCount=1")
        return admin_users
    
    def find_path_to_domain_admin(self) -> List[Dict[str, Any]]:
        """Find shortest paths from users to Domain Admins"""
        logger.info("Finding paths to Domain Admins")
        
        query = """
        MATCH (u:User {enabled: true}), (g:Group)
        WHERE g.objectid ENDS WITH "-512"
        MATCH p=shortestPath((u)-[r*1..]->(g))
        WHERE NONE(rel in r WHERE type(rel)="GetChanges" OR type(rel)="GetChangesAll")
        RETURN u.name as user, [x IN NODES(p) | LABELS(x)[0] + ": " + x.name] as path_nodes,
               [x IN RELATIONSHIPS(p) | TYPE(x)] as path_rels, LENGTH(p) as path_length
        ORDER BY path_length ASC
        LIMIT 20
        """
        
        paths = self._run_query(query)
        # Filter out paths that include computers (which may have broken edges)
        filtered_paths = [p for p in paths if not any("Computer:" in node for node in p.get("path_nodes", []))]
        
        self.users_with_path_to_da = filtered_paths
        
        logger.info(f"Found {len(filtered_paths)} users with path to Domain Admins")
        return filtered_paths
    
    def find_gpo_impacts(self) -> List[Dict[str, Any]]:
        """Find GPOs that affect high value targets"""
        logger.info("Finding GPOs that affect high value targets")
        
        query = """
        MATCH (g:GPO)
        MATCH (t)
        WHERE (t:User OR t:Computer) AND 
              ((t)-[:MemberOf*1..]->(:Group) WHERE .objectid ENDS WITH "-512" OR .objectid ENDS WITH "-516" OR .objectid ENDS WITH "-519")
        MATCH p=((g)-[:GPLink]->(container)-[:Contains*1..]->(t))
        RETURN g.name as gpo, t.name as target, labels(t)[0] as target_type,
               CASE 
                  WHEN .objectid ENDS WITH "-512" THEN 'Domain Admin' 
                  WHEN .objectid ENDS WITH "-516" THEN 'Domain Controller'
                  WHEN .objectid ENDS WITH "-519" THEN 'Enterprise Admin'
               END as role
        """
        
        gpo_impacts = self._run_query(query)
        self.gpo_impacts = gpo_impacts
        
        logger.info(f"Found {len(gpo_impacts)} GPO impacts on high value targets")
        return gpo_impacts
    
    def find_computers_with_admin_local(self) -> List[Dict[str, Any]]:
        """Find computers where non-privileged users have local admin rights"""
        logger.info("Finding computers with non-privileged users as local admins")
        
        query = """
        MATCH (u:User)-[r:AdminTo]->(c:Computer)
        WHERE NOT u.admincount=true AND u.enabled=true 
        RETURN c.name as computer, c.operatingsystem as os, 
               collect(DISTINCT u.name) as admin_users, count(DISTINCT u) as admin_count
        ORDER BY admin_count DESC
        """
        
        computers = self._run_query(query)
        self.computers_with_admin_local = computers
        
        logger.info(f"Found {len(computers)} computers with non-privileged users as local admins")
        return computers
    
    def find_domain_trusts(self) -> List[Dict[str, Any]]:
        """Find domain trusts"""
        logger.info("Finding domain trusts")
        
        query = """
        MATCH (d1:Domain)-[r:TrustedBy|Trusts]->(d2:Domain)
        RETURN d1.name as domain1, d2.name as domain2, type(r) as trust_type,
               r.sidfiltering as sid_filtering, r.transitive as transitive, 
               CASE 
                 WHEN r.direction=1 THEN 'Inbound' 
                 WHEN r.direction=2 THEN 'Outbound'
                 WHEN r.direction=3 THEN 'Bidirectional'
                 ELSE 'Unknown'
               END as direction
        """
        
        trusts = self._run_query(query)
        self.domain_trusts = trusts
        
        logger.info(f"Found {len(trusts)} domain trust relationships")
        return trusts
    
    def find_dcsync_rights(self) -> List[Dict[str, Any]]:
        """Find users with DCSync rights"""
        logger.info("Finding users with DCSync rights")
        
        query = """
        MATCH (u)-[:MemberOf*0..]->(g:Group)-[r:GetChanges*1..]->(d:Domain)
        MATCH (g)-[r2:GetChangesAll*1..]->(d)
        RETURN u.name as name, labels(u)[0] as type, d.name as domain
        """
        
        dcsync_users = self._run_query(query)
        self.dcsync_rights = dcsync_users
        
        logger.info(f"Found {len(dcsync_users)} principals with DCSync rights")
        return dcsync_users
    
    def find_owned_objects(self) -> List[Dict[str, Any]]:
        """Find objects marked as owned in BloodHound"""
        logger.info("Finding owned objects")
        
        query = """
        MATCH (n) 
        WHERE n.owned=true
        RETURN n.name as name, labels(n)[0] as type
        """
        
        owned = self._run_query(query)
        self.owned_objects = owned
        
        logger.info(f"Found {len(owned)} owned objects")
        return owned
    
    def find_certificate_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Find certificate template vulnerabilities (ESC1-ESC8)"""
        logger.info("Finding certificate template vulnerabilities")
        
        query = """
        MATCH (n:User)-[r:Enroll|GenericAll|GenericWrite|Owns|WriteDacl|WriteOwner|AllExtendedRights]->(t:GPO)
        WHERE t.name CONTAINS "Certificate"
        RETURN n.name as principal, t.name as template, type(r) as relationship
        """
        
        cert_vulns = self._run_query(query)
        self.certificate_vulnerabilities = cert_vulns
        
        logger.info(f"Found {len(cert_vulns)} potential certificate vulnerabilities")
        return cert_vulns
    
    def find_critical_attack_paths(self) -> List[Dict[str, Any]]:
        """Find critical attack paths to sensitive objects"""
        logger.info("Finding critical attack paths")
        
        critical_paths = []
        
        # Find paths from owned objects to Domain Admins if any objects are owned
        if self.owned_objects:
            owned_names = [obj["name"] for obj in self.owned_objects]
            quoted_names = ", ".join([f"'{name}'" for name in owned_names])
            
            query = f"""
            MATCH (o), (g:Group)
            WHERE o.name IN [{quoted_names}] AND g.objectid ENDS WITH "-512"
            MATCH p=shortestPath((o)-[r*1..]->(g))
            WHERE NONE(rel in r WHERE type(rel)="GetChanges" OR type(rel)="GetChangesAll")
            RETURN o.name as source, labels(o)[0] as source_type, 'Domain Admins' as target,
                   [x IN NODES(p) | LABELS(x)[0] + ": " + x.name] as path_nodes,
                   [x IN RELATIONSHIPS(p) | TYPE(x)] as path_rels, LENGTH(p) as path_length
            ORDER BY path_length ASC
            LIMIT 5
            """
            
            owned_paths = self._run_query(query)
            critical_paths.extend(owned_paths)
        
        # Find other critical paths (e.g., users with GenericAll on Domain Admins)
        query = """
        MATCH (u:User {enabled: true}), (g:Group)
        WHERE g.objectid ENDS WITH "-512"
        MATCH p=shortestPath((u)-[r*1..]->(g))
        WHERE ANY(rel in r WHERE type(rel) IN ["GenericAll", "WriteDacl", "WriteOwner", "Owns", "AddMember"])
        RETURN u.name as source, 'User' as source_type, 'Domain Admins' as target,
               [x IN NODES(p) | LABELS(x)[0] + ": " + x.name] as path_nodes,
               [x IN RELATIONSHIPS(p) | TYPE(x)] as path_rels, LENGTH(p) as path_length
        ORDER BY path_length ASC
        LIMIT 5
        """
        
        critical_rels_paths = self._run_query(query)
        critical_paths.extend(critical_rels_paths)
        
        self.critical_attack_paths = critical_paths
        
        logger.info(f"Found {len(critical_paths)} critical attack paths")
        return critical_paths
    
    def analyze_all(self) -> Dict[str, Any]:
        """Run all analysis functions"""
        logger.info("Starting comprehensive BloodHound analysis")
        
        results = {
            "timestamp": datetime.now().isoformat(),
            "domain_info": self.get_domain_info(),
            "high_value_targets": self.find_high_value_targets(),
            "kerberoastable_users": self.find_kerberoastable_users(),
            "asreproastable_users": self.find_asreproastable_users(),
            "admin_users": self.find_admin_users(),
            "users_with_path_to_da": self.find_path_to_domain_admin(),
            "domain_trusts": self.find_domain_trusts(),
            "dcsync_rights": self.find_dcsync_rights(),
            "owned_objects": self.find_owned_objects(),
            "certificate_vulnerabilities": self.find_certificate_vulnerabilities(),
            "critical_attack_paths": self.find_critical_attack_paths(),
            "computers_with_admin_local": self.find_computers_with_admin_local(),
            "gpo_impacts": self.find_gpo_impacts()
        }
        
        return results
    
    def format_finding(self, finding_name: str, records: List[Dict[str, Any]], columns: List[str]) -> str:
        """Format findings into a readable text table"""
        if not records:
            return f"{finding_name}:\nNone found\n"
        
        result = f"{finding_name} ({len(records)} found):\n"
        
        # Calculate column widths based on content
        col_widths = {}
        for col in columns:
            col_values = [str(record.get(col, "")) for record in records]
            col_widths[col] = max(len(col), max([len(val) for val in col_values]) if col_values else 0)
        
        # Create header row with separators
        header = " | ".join(f"{col.ljust(col_widths[col])}" for col in columns)
        separator = "-+-".join("-" * col_widths[col] for col in columns)
        
        result += header + "\n" + separator + "\n"
        
        # Add data rows
        for record in records:
            row_values = [str(record.get(col, "")).ljust(col_widths[col]) for col in columns]
            result += " | ".join(row_values) + "\n"
        
        return result + "\n"
    
    def format_attack_path(self, path: Dict[str, Any]) -> str:
        """Format an attack path in a more readable way"""
        source = path.get("source", "Unknown")
        target = path.get("target", "Unknown")
        path_length = path.get("path_length", 0)
        
        # Combine nodes and relationships for visualization
        nodes = path.get("path_nodes", [])
        rels = path.get("path_rels", [])
        
        path_visualization = ""
        for i, node in enumerate(nodes):
            path_visualization += node
            if i < len(nodes) - 1 and i < len(rels):
                path_visualization += f" -{rels[i]}-> "
        
        return f"Path from {source} to {target} (Length: {path_length}):\n{path_visualization}\n"
    
    def generate_report(self, results: Dict[str, Any] = None) -> str:
        """Generate a comprehensive text report from analysis results"""
        if results is None:
            results = self.analyze_all()
        
        report = "==========================================\n"
        report += "    BLOODHOUND ANALYSIS REPORT          \n"
        report += "==========================================\n\n"
        report += f"Report generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        # Domain Information
        report += "DOMAIN INFORMATION:\n"
        report += "==================\n\n"
        
        domains = results.get("domain_info", {}).get("domains", [])
        
        for domain in domains:
            report += f"Domain: {domain.get('domain')}\n"
            report += f"Functional Level: {domain.get('functional_level')}\n"
            
            # Find matching user count
            for uc in results.get("domain_info", {}).get("user_counts", []):
                if uc.get("domain") == domain.get("domain"):
                    report += f"User Count: {uc.get('user_count')}\n"
            
            # Find matching computer count
            for cc in results.get("domain_info", {}).get("computer_counts", []):
                if cc.get("domain") == domain.get("domain"):
                    report += f"Computer Count: {cc.get('computer_count')}\n"
            
            # List domain controllers
            domain_name = domain.get("domain")
            dcs = results.get("domain_info", {}).get("domain_controllers", {}).get(domain_name, [])
            if dcs:
                report += f"\nDomain Controllers ({len(dcs)}):\n"
                for dc in dcs:
                    report += f"  - {dc.get('name')} ({dc.get('os')})\n"
            
            report += "\n"
        
        # High-Value Targets
        report += self.format_finding(
            "HIGH VALUE TARGETS",
            results.get("high_value_targets", []),
            ["name", "type", "os"]
        )
        
        # Kerberoastable Users
        report += self.format_finding(
            "KERBEROASTABLE USERS",
            results.get("kerberoastable_users", []),
            ["name", "display_name", "enabled"]
        )
        
        # AS-REP Roastable Users
        report += self.format_finding(
            "AS-REP ROASTABLE USERS",
            results.get("asreproastable_users", []),
            ["name", "display_name", "enabled"]
        )
        
        # DCSync Rights
        report += self.format_finding(
            "USERS WITH DCSYNC RIGHTS",
            results.get("dcsync_rights", []),
            ["name", "type", "domain"]
        )
        
        # Domain Trusts
        report += self.format_finding(
            "DOMAIN TRUSTS",
            results.get("domain_trusts", []),
            ["domain1", "domain2", "trust_type", "direction"]
        )
        
        # Owned Objects
        if results.get("owned_objects", []):
            report += self.format_finding(
                "OWNED OBJECTS",
                results.get("owned_objects", []),
                ["name", "type"]
            )
        
        # Critical Attack Paths
        critical_paths = results.get("critical_attack_paths", [])
        if critical_paths:
            report += "CRITICAL ATTACK PATHS:\n"
            report += "=====================\n\n"
            
            for i, path in enumerate(critical_paths, 1):
                report += f"Path {i}:\n"
                report += self.format_attack_path(path)
                report += "\n"
        
        # Paths to Domain Admin
        paths_to_da = results.get("users_with_path_to_da", [])
        if paths_to_da:
            report += "PATHS TO DOMAIN ADMIN:\n"
            report += "=====================\n\n"
            
            # Only show the first 5 paths to avoid overwhelming
            for i, path in enumerate(paths_to_da[:5], 1):
                report += f"Path {i} - User: {path.get('user')} (Length: {path.get('path_length')})\n"
                
                # Format path
                nodes = path.get("path_nodes", [])
                rels = path.get("path_rels", [])
                
                path_str = ""
                for j, node in enumerate(nodes):
                    path_str += node
                    if j < len(nodes) - 1 and j < len(rels):
                        path_str += f" -{rels[j]}-> "
                
                report += path_str + "\n\n"
            
            if len(paths_to_da) > 5:
                report += f"... and {len(paths_to_da) - 5} more paths\n\n"
        
        # Certificate Vulnerabilities
        if results.get("certificate_vulnerabilities", []):
            report += self.format_finding(
                "CERTIFICATE TEMPLATE VULNERABILITIES",
                results.get("certificate_vulnerabilities", []),
                ["principal", "template", "relationship"]
            )
        
        # Computers with non-privileged users as local admins
        report += self.format_finding(
            "COMPUTERS WITH NON-PRIVILEGED LOCAL ADMINS",
            results.get("computers_with_admin_local", []),
            ["computer", "os", "admin_count"]
        )
        
        # Recommendations
        report += "RECOMMENDATIONS:\n"
        report += "===============\n\n"
        
        # Generate targeted recommendations based on findings
        recommendations = []
        
        if results.get("kerberoastable_users", []):
            recommendations.append("1. Perform Kerberoasting attacks against the identified service accounts and attempt to crack the hashes.")
        
        if results.get("asreproastable_users", []):
            recommendations.append("2. Perform AS-REP Roasting against users with DONT_REQ_PREAUTH and attempt to crack the hashes.")
        
        if results.get("dcsync_rights", []):
            recommendations.append("3. Use the identified DCSync rights to extract password hashes from the domain.")
        
        if results.get("critical_attack_paths", []):
            recommendations.append("4. Exploit the identified critical attack paths to escalate privileges to Domain Admin.")
        
        if results.get("computers_with_admin_local", []):
            recommendations.append("5. Leverage non-privileged users with local admin rights for lateral movement.")
        
        if results.get("certificate_vulnerabilities", []):
            recommendations.append("6. Exploit vulnerable certificate templates to obtain certificates that can be used for authentication.")
        
        if results.get("domain_trusts", []):
            recommendations.append("7. Explore trust relationships for potential cross-domain privilege escalation.")
        
        if not recommendations:
            recommendations.append("No specific attack recommendations based on current findings.")
        
        for rec in recommendations:
            report += f"- {rec}\n"
        
        return report
    
    def save_report(self, report: str, filename: str = None) -> str:
        """Save the report to a file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"bloodhound_analysis_{timestamp}.txt"
        
        filepath = self.output_dir / filename
        
        with open(filepath, 'w') as f:
            f.write(report)
        
        logger.info(f"Report saved to {filepath}")
        return str(filepath)
    
    def save_json_results(self, results: Dict[str, Any], filename: str = None) -> str:
        """Save analysis results as JSON"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"bloodhound_analysis_{timestamp}.json"
        
        filepath = self.output_dir / filename
        
        # Clean results to make them JSON serializable
        def clean_for_json(obj):
            if isinstance(obj, (list, tuple)):
                return [clean_for_json(item) for item in obj]
            elif isinstance(obj, dict):
                return {k: clean_for_json(v) for k, v in obj.items()}
            elif isinstance(obj, (str, int, float, bool, type(None))):
                return obj
            else:
                return str(obj)
        
        clean_results = clean_for_json(results)
        
        with open(filepath, 'w') as f:
            json.dump(clean_results, f, indent=2)
        
        logger.info(f"JSON results saved to {filepath}")
        return str(filepath)

def main():
    parser = argparse.ArgumentParser(description='BloodHound Analysis Automation')
    parser.add_argument('--uri', required=True, help='Neo4j URI (e.g., bolt://localhost:7687)')
    parser.add_argument('--username', required=True, help='Neo4j username')
    parser.add_argument('--password', required=True, help='Neo4j password')
    parser.add_argument('--output-dir', help='Output directory for reports')
    parser.add_argument('--report-file', help='Specific filename for the report')
    parser.add_argument('--json-file', help='Specific filename for JSON results')
    parser.add_argument('--verbose', action='store_true', help='Enable verbose logging')
    
    args = parser.parse_args()
    
    # Set logging level based on verbose flag
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        # Add more detailed formatting for debug logs
        for handler in logger.handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setFormatter(logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s'))
    
    logger.info("BloodHound Analysis starting")
    
    try:
        # Initialize the analyzer
        analyzer = BloodHoundAnalyzer(args.uri, args.username, args.password, args.output_dir)
        
        # Run the analysis
        logger.info("Running analysis")
        results = analyzer.analyze_all()
        
        # Generate and save the report
        logger.info("Generating report")
        report = analyzer.generate_report(results)
        report_path = analyzer.save_report(report, args.report_file)
        
        # Save JSON results
        logger.info("Saving JSON results")
        json_path = analyzer.save_json_results(results, args.json_file)
        
        # Close connections
        analyzer.close()
        
        logger.info(f"Analysis complete. Report saved to {report_path}")
        logger.info(f"JSON results saved to {json_path}")
        
        # Display report path to stdout
        print(f"\nReport saved to: {report_path}")
        print(f"JSON results saved to: {json_path}")
        
    except Exception as e:
        logger.error(f"Error during analysis: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()