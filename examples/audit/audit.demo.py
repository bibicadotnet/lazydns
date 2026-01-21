#!/usr/bin/env python3
"""
Audit Plugin Demo - Security Event Simulator

This script simulates various security events to demonstrate the audit plugin's
logging capabilities.

Requirements:
    pip install dnspython

Usage:
    # Start the audit demo server first:
    cargo run -- -c examples/audit/audit.demo.yaml

    # In another terminal, run this script:
    python3 examples/audit/audit.demo.py

    # Monitor the logs in real-time:
    tail -f examples/audit/log/queries.log | jq '.'
    tail -f examples/audit/log/security.log | jq '.'
"""

import asyncio
import sys
import time
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple

try:
    import dns.resolver
    import dns.rdatatype
    import dns.exception
except ImportError:
    print("Error: dnspython is required. Install it with:")
    print("  pip install dnspython")
    sys.exit(1)


class AuditDemoSimulator:
    """Simulates security events for the audit plugin demo."""

    def __init__(
        self,
        target_host: str = "127.0.0.1",
        target_port: int = 5354,
        log_dir: str = "examples/audit/log",
    ):
        self.target_host = target_host
        self.target_port = target_port
        self.log_dir = Path(log_dir)
        
        # Configure DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = [target_host]
        self.resolver.port = target_port
        
        # Test domains
        self.normal_domains = [
            "example.com",
            "google.com",
            "github.com",
            "cloudflare.com",
            "dns.google",
        ]
        
        self.blocked_domains = [
            "blocked-domain.local",
            "bad.example.com",
            "malware.test",
        ]
        
        self.high_volume_domains = [f"test{i}.com" for i in range(250)]

    def query_domain(self, domain: str, timeout: int = 2) -> Tuple[bool, str]:
        """
        Query a domain and return (success, message).
        """
        try:
            result = self.resolver.resolve(domain, "A", lifetime=timeout)
            answers = [str(rr) for rr in result]
            return True, f"{domain} -> {', '.join(answers)}"
        except dns.exception.Timeout:
            return False, f"{domain} -> TIMEOUT"
        except dns.resolver.NXDOMAIN:
            return False, f"{domain} -> NXDOMAIN"
        except dns.resolver.NoAnswer:
            return False, f"{domain} -> NO ANSWER"
        except Exception as e:
            return False, f"{domain} -> ERROR: {str(e)}"

    def print_section(self, title: str):
        """Print a formatted section header."""
        print("\n" + "=" * 70)
        print(f"  {title}")
        print("=" * 70)

    def print_event(self, event_type: str, message: str, status: str = ""):
        """Print a formatted event message."""
        status_str = f" [{status}]" if status else ""
        print(f"  ▸ {event_type:30} {message:30}{status_str}")

    def demo_1_normal_queries(self):
        """Scenario 1: Normal DNS queries - logged to queries.log"""
        self.print_section("SCENARIO 1: Normal DNS Queries")
        print("These queries will be logged to examples/audit/log/queries.log with full response details.\n")

        for domain in self.normal_domains:
            success, message = self.query_domain(domain)
            status = "✓ OK" if success else "✗ FAILED"
            self.print_event("NORMAL QUERY", message, status)
            time.sleep(0.2)  # Small delay between queries

    def demo_2_blocked_domains(self):
        """Scenario 2: Blocked domain queries - triggers blocked_domain_query event"""
        self.print_section("SCENARIO 2: Blocked Domain Queries")
        print("These queries match the blocked domain list and get blackholed.\n")

        for domain in self.blocked_domains:
            success, message = self.query_domain(domain, timeout=1)
            status = "🚫 BLOCKED" if not success else "✓ OK"
            self.print_event("BLOCKED DOMAIN", message, status)
            time.sleep(0.3)

    def demo_3_rate_limit(self):
        """Scenario 3: Rate limit exceeded - triggers rate_limit_exceeded event"""
        self.print_section("SCENARIO 3: Rate Limit Exceeded")
        print("Sending 210+ queries in rapid succession (limit is 200/60s).\n")
        print("This will trigger rate_limit_exceeded security events.\n")

        success_count = 0
        refused_count = 0

        print("  Sending queries in parallel...\n")

        # Send queries in rapid parallel batches
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for i, domain in enumerate(self.high_volume_domains[:220]):
                future = executor.submit(self.query_domain, domain, timeout=3)
                futures.append((i + 1, domain, future))

            # Wait for results and display progress
            for idx, domain, future in futures:
                try:
                    success, message = future.result(timeout=5)
                    if success:
                        success_count += 1
                        status = "✓ OK"
                    else:
                        refused_count += 1
                        status = "✗ REFUSED"
                    
                    if idx % 20 == 0:
                        self.print_event(f"QUERY {idx:3d}/220", domain, status)
                except Exception as e:
                    refused_count += 1
                    self.print_event(f"QUERY {idx:3d}/220", domain, "✗ ERROR")

        print(f"\n  ✓ Accepted: {success_count}")
        print(f"  ✗ Refused/Timeout: {refused_count}")
        print(f"  Note: Rate limit exceeded events should be in examples/audit/log/security.log")

    def demo_4_malformed_queries(self):
        """Scenario 4: Malformed queries - triggers malformed_query event"""
        self.print_section("SCENARIO 4: Malformed Queries")
        print("Sending malformed domain names to trigger validation errors.\n")

        malformed = [
            "",  # empty
            "invalid..domain",
            "test\x00bad",
            "a" * 300,
        ]

        for domain in malformed:
            try:
                success, message = self.query_domain(domain, timeout=1)
                status = "✓ OK" if success else "✗ REJECTED"
                self.print_event("MALFORMED", message, status)
            except Exception as e:
                self.print_event("MALFORMED", str(e), "✗ ERROR")
            time.sleep(0.2)

    def demo_5_query_patterns(self):
        """Scenario 5: Various query patterns"""
        self.print_section("SCENARIO 5: Query Pattern Analysis")
        print("Testing different query types and patterns.\n")

        test_cases = [
            ("example.com", "Standard A record"),
            ("google.com", "Large response (multiple A records)"),
            ("example.com", "Cached response (second query)"),
            ("nonexistent123456.local", "NXDOMAIN response"),
        ]

        for domain, description in test_cases:
            success, message = self.query_domain(domain)
            status = "✓ OK" if success else "✗ NXDOMAIN"
            print(f"  {domain:25} - {description:30} [{status}]")
            time.sleep(0.3)

    def demo_6_upstream_timeout(self):
        """Scenario 6: Upstream timeout/failure - triggers query_timeout/upstream_failure"""
        self.print_section("SCENARIO 6: Upstream Timeout / Failure")
        print("Querying domains configured to trigger upstream errors.\n")
        
        # Test upstream failure (immediate error)
        print("  - Testing Upstream Failure (connection refused)...")
        success, message = self.query_domain("upstream-fail.test", timeout=1)
        self.print_event("UPSTREAM FAILURE", message, "✗ ERROR")
        
        # Test upstream timeout (delayed error)
        print("\n  - Testing Upstream Timeout (drops packets)...")
        success, message = self.query_domain("timeout.test", timeout=2)
        self.print_event("UPSTREAM TIMEOUT", message, "✗ TIMEOUT")
        
        time.sleep(0.5)

    def demo_7_acl_denied(self):
        """Scenario 7: ACL denied - triggers acl_denied event"""
        self.print_section("SCENARIO 7: ACL Denied")
        print("Querying domain restricted by ACL rules (acl-deny.test).\n")
        domain = "acl-deny.test"
        success, message = self.query_domain(domain, timeout=1)
        status = "✓ OK" if success else "🚫 DENIED"
        self.print_event("ACL DENIED", message, status)
        time.sleep(0.5)

    def show_log_summary(self):
        """Display summary of generated logs."""
        self.print_section("LOG SUMMARY")

        queries_log = self.log_dir / "queries.log"
        security_log = self.log_dir / "security.log"

        print("\n  Query Log (examples/audit/log/queries.log):")
        if queries_log.exists():
            with open(queries_log, "r") as f:
                lines = f.readlines()
            print(f"    Total entries: {len(lines)}")
            
            # Analyze query types
            query_types = {}
            response_codes = {}
            for line in lines:
                try:
                    entry = json.loads(line)
                    qtype = entry.get("qtype", "unknown")
                    rcode = entry.get("rcode", "unknown")
                    query_types[qtype] = query_types.get(qtype, 0) + 1
                    response_codes[rcode] = response_codes.get(rcode, 0) + 1
                except:
                    pass
            
            if query_types:
                print(f"    Query types: {dict(query_types)}")
            if response_codes:
                print(f"    Response codes: {dict(response_codes)}")
            
            # Show last 3 entries
            print(f"\n    Last 3 queries:")
            for line in lines[-3:]:
                try:
                    entry = json.loads(line)
                    print(f"      - {entry['qname']:30} {entry['rcode']:10} ({entry.get('response_time_ms', 0)}ms)")
                except:
                    pass
        else:
            print("    ✗ Log file not found")

        print("\n  Security Event Log (examples/audit/log/security.log):")
        if security_log.exists():
            with open(security_log, "r") as f:
                lines = f.readlines()
            print(f"    Total events: {len(lines)}")
            
            # Analyze event types
            event_types = {}
            for line in lines:
                try:
                    entry = json.loads(line)
                    event_type = entry.get("event_type", "unknown")
                    event_types[event_type] = event_types.get(event_type, 0) + 1
                except:
                    pass
            
            if event_types:
                print(f"    Event types: {dict(event_types)}")
            
            # Show last 3 events
            if lines:
                print(f"\n    Last 3 events:")
                for line in lines[-3:]:
                    try:
                        entry = json.loads(line)
                        print(f"      - {entry['event_type']:25} {entry.get('message', '')}")
                    except:
                        pass
        else:
            print("    ℹ  No security events recorded (this is normal if no events were triggered)")

    def run_all_scenarios(self):
        """Run all demo scenarios."""
        print("\n")
        print("╔" + "=" * 68 + "╗")
        print("║" + " " * 15 + "AUDIT PLUGIN DEMO - SECURITY EVENT SIMULATOR" + " " * 9 + "║")
        print("╚" + "=" * 68 + "╝")

        print(f"\nTarget: {self.target_host}:{self.target_port}")
        print(f"Log directory: {self.log_dir}")

        try:
            # Test connectivity
            print("\nTesting connectivity...")
            success, _ = self.query_domain("example.com", timeout=2)
            if not success:
                print("✗ Cannot connect to DNS server. Make sure it's running:")
                print(f"  cargo run --features audit -- -c examples/audit/audit.demo.yaml")
                return False
            print("✓ Connected to DNS server")

            # Run scenarios
            self.demo_1_normal_queries()
            time.sleep(1)

            self.demo_2_blocked_domains()
            time.sleep(1)

            self.demo_3_rate_limit()
            time.sleep(1)

            self.demo_4_malformed_queries()
            time.sleep(1)

            self.demo_5_query_patterns()
            time.sleep(1)

            self.demo_6_upstream_timeout()
            time.sleep(1)

            self.demo_7_acl_denied()
            time.sleep(1)

            self.show_log_summary()

            print("\n" + "=" * 70)
            print("  ✓ Demo completed!")
            print("=" * 70)
            print("\nView logs in real-time with:")
            print("  tail -f examples/audit/log/queries.log | jq '.'")
            print("  tail -f examples/audit/log/security.log | jq '.'")
            print("\nAnalyze logs with:")
            print("  jq 'group_by(.rcode) | map({code: .[0].rcode, count: length})' examples/audit/log/queries.log")
            print("  jq 'group_by(.event_type) | map({type: .[0].event_type, count: length})' examples/audit/log/security.log")
            print()

            return True

        except KeyboardInterrupt:
            print("\n\n✗ Demo interrupted by user")
            return False
        except Exception as e:
            print(f"\n✗ Error: {e}")
            import traceback
            traceback.print_exc()
            return False


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Audit Plugin Demo - Security Event Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with default settings
  python3 examples/audit/audit.demo.py

  # Target a different server
  python3 examples/audit/audit.demo.py --host 192.168.1.100 --port 53

  # Use different log directory
  python3 examples/audit/audit.demo.py --log-dir examples/audit/log
        """,
    )

    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Target DNS server host (default: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=5354,
        help="Target DNS server port (default: 5354)",
    )
    parser.add_argument(
        "--log-dir",
        default="examples/audit/log",
        help="Log directory path (default: examples/audit/log)",
    )

    args = parser.parse_args()
    simulator = AuditDemoSimulator(
        target_host=args.host,
        target_port=args.port,
        log_dir=args.log_dir,
    )

    success = simulator.run_all_scenarios()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
