#!/usr/bin/env python3
"""
Configure Wazuh Index Template for GCP Security Logs

This script creates a custom index template in Wazuh to properly index
GCP security application log fields.

Usage:
    python3 configure_index.py --password YOUR_ADMIN_PASSWORD
    
    Or with environment variable:
    export WAZUH_PASSWORD="YOUR_ADMIN_PASSWORD"
    python3 configure_index.py
"""

import argparse
import json
import subprocess
import sys
import time
from typing import Dict, Tuple


# Index template definition
INDEX_TEMPLATE = {
    "index_patterns": ["wazuh-alerts-*"],
    "priority": 1,
    "template": {
        "settings": {
            "number_of_shards": 1,
            "number_of_replicas": 0,
            "index.mapping.total_fields.limit": 2000
        },
        "mappings": {
            "properties": {
                "data": {
                    "properties": {
                        "gcp": {
                            "properties": {
                                "jsonPayload": {
                                    "properties": {
                                        "event_type": {
                                            "type": "keyword",
                                            "fields": {
                                                "text": {
                                                    "type": "text"
                                                }
                                            }
                                        },
                                        "result": {
                                            "type": "keyword"
                                        },
                                        "reason": {
                                            "type": "keyword"
                                        },
                                        "severity": {
                                            "type": "keyword"
                                        },
                                        "email": {
                                            "type": "keyword",
                                            "fields": {
                                                "text": {
                                                    "type": "text"
                                                }
                                            }
                                        },
                                        "source_ip": {
                                            "type": "ip"
                                        },
                                        "endpoint": {
                                            "type": "keyword",
                                            "fields": {
                                                "text": {
                                                    "type": "text"
                                                }
                                            }
                                        },
                                        "method": {
                                            "type": "keyword"
                                        },
                                        "action": {
                                            "type": "keyword"
                                        },
                                        "user_id": {
                                            "type": "keyword"
                                        },
                                        "environment": {
                                            "type": "keyword"
                                        },
                                        "request_id": {
                                            "type": "keyword"
                                        },
                                        "lab_mode": {
                                            "type": "keyword"
                                        },
                                        "vulnerability": {
                                            "type": "keyword"
                                        },
                                        "timestamp": {
                                            "type": "date",
                                            "format": "strict_date_optional_time||epoch_millis"
                                        },
                                        "exported_count": {
                                            "type": "long"
                                        },
                                        "error": {
                                            "type": "text",
                                            "fields": {
                                                "keyword": {
                                                    "type": "keyword",
                                                    "ignore_above": 256
                                                }
                                            }
                                        },
                                        "filename": {
                                            "type": "keyword"
                                        },
                                        "resource_identifiers": {
                                            "properties": {
                                                "image_id": {
                                                    "type": "keyword"
                                                },
                                                "bucket": {
                                                    "type": "keyword"
                                                },
                                                "object_path": {
                                                    "type": "text",
                                                    "fields": {
                                                        "keyword": {
                                                            "type": "keyword",
                                                            "ignore_above": 512
                                                        }
                                                    }
                                                },
                                                "actual_owner": {
                                                    "type": "keyword"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}


def run_remote_command(command: str, check: bool = True) -> Tuple[int, str, str]:
    """
    Execute a command on the remote Wazuh VM via gcloud compute ssh
    
    Args:
        command: The command to execute
        check: Whether to raise an exception on non-zero exit code
        
    Returns:
        Tuple of (exit_code, stdout, stderr)
    """
    ssh_command = [
        'gcloud', 'compute', 'ssh', 'wazuh-aio',
        '--zone', 'us-central1-a',
        '--project', 'apps-data-monitoring',
        '--command', command
    ]
    
    try:
        result = subprocess.run(
            ssh_command,
            capture_output=True,
            text=True,
            check=check
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr


def check_connection() -> bool:
    """Test SSH connection to Wazuh VM"""
    print("🔍 Testing SSH connection to Wazuh VM...")
    exit_code, stdout, stderr = run_remote_command('echo "Connection OK"', check=False)
    
    if exit_code == 0:
        print("✅ SSH connection successful")
        return True
    else:
        print(f"❌ SSH connection failed: {stderr}")
        return False


def check_indexer_health(password: str) -> bool:
    """Check if Wazuh indexer is healthy"""
    print("🔍 Checking Wazuh indexer health...")
    
    command = f'curl -s -k -u "admin:{password}" https://localhost:9200/_cluster/health'
    exit_code, stdout, stderr = run_remote_command(command, check=False)
    
    if exit_code == 0 and stdout:
        try:
            health = json.loads(stdout)
            status = health.get('status', 'unknown')
            print(f"✅ Wazuh indexer is {status}")
            return status in ['yellow', 'green']
        except json.JSONDecodeError:
            print(f"⚠️  Could not parse health response: {stdout}")
            return False
    else:
        print(f"❌ Failed to check indexer health: {stderr}")
        return False


def create_index_template(password: str) -> bool:
    """Create the custom index template"""
    print("\n📝 Creating custom index template for GCP security fields...")
    
    # Save template to remote file
    template_json = json.dumps(INDEX_TEMPLATE, indent=2)
    
    # Escape single quotes for bash
    template_json_escaped = template_json.replace("'", "'\\''")
    
    # Create temp file on remote
    create_file_cmd = f"echo '{template_json_escaped}' > /tmp/gcp-index-template.json"
    exit_code, stdout, stderr = run_remote_command(create_file_cmd, check=False)
    
    if exit_code != 0:
        print(f"❌ Failed to create template file: {stderr}")
        return False
    
    print("✅ Template file created on remote VM")
    
    # Apply the template
    print("📤 Applying index template to Wazuh indexer...")
    apply_cmd = f'''curl -s -k -w "\\n%{{http_code}}" \
        -X PUT "https://localhost:9200/_index_template/gcp-security-fields" \
        -u "admin:{password}" \
        -H 'Content-Type: application/json' \
        -d @/tmp/gcp-index-template.json'''
    
    exit_code, stdout, stderr = run_remote_command(apply_cmd, check=False)
    
    if exit_code == 0:
        lines = stdout.strip().split('\n')
        http_code = lines[-1] if lines else "000"
        response_body = '\n'.join(lines[:-1]) if len(lines) > 1 else ""
        
        if http_code in ['200', '201']:
            print(f"✅ Index template created successfully (HTTP {http_code})")
            try:
                response = json.loads(response_body)
                if response.get('acknowledged'):
                    print("✅ Template acknowledged by indexer")
                return True
            except json.JSONDecodeError:
                print("✅ Template applied (could not parse response)")
                return True
        else:
            print(f"⚠️  Unexpected HTTP code: {http_code}")
            print(f"Response: {response_body}")
            return False
    else:
        print(f"❌ Failed to apply template: {stderr}")
        return False


def verify_template(password: str) -> bool:
    """Verify the template was created"""
    print("\n🔍 Verifying index template...")
    
    verify_cmd = f'curl -s -k -u "admin:{password}" https://localhost:9200/_index_template/gcp-security-fields'
    exit_code, stdout, stderr = run_remote_command(verify_cmd, check=False)
    
    if exit_code == 0 and stdout:
        try:
            response = json.loads(stdout)
            if 'index_templates' in response and len(response['index_templates']) > 0:
                template_info = response['index_templates'][0]
                template_name = template_info.get('name', 'unknown')
                patterns = template_info.get('index_template', {}).get('index_patterns', [])
                
                print(f"✅ Template '{template_name}' exists")
                print(f"   Index patterns: {', '.join(patterns)}")
                
                # Check field mappings
                mappings = template_info.get('index_template', {}).get('template', {}).get('mappings', {})
                gcp_payload_fields = (mappings.get('properties', {})
                                     .get('data', {})
                                     .get('properties', {})
                                     .get('gcp', {})
                                     .get('properties', {})
                                     .get('jsonPayload', {})
                                     .get('properties', {}))
                
                if gcp_payload_fields:
                    field_count = len(gcp_payload_fields)
                    print(f"✅ Template includes {field_count} custom GCP fields")
                    print(f"   Sample fields: {', '.join(list(gcp_payload_fields.keys())[:5])}...")
                    return True
                else:
                    print("⚠️  Template exists but GCP fields not found")
                    return False
            else:
                print("❌ Template not found")
                return False
        except json.JSONDecodeError:
            print(f"⚠️  Could not parse verification response: {stdout}")
            return False
    else:
        print(f"❌ Failed to verify template: {stderr}")
        return False


def list_indexed_fields(password: str) -> bool:
    """List what fields are currently indexed"""
    print("\n📋 Checking currently indexed fields...")
    
    # Get mapping for the latest index
    cmd = f'curl -s -k -u "admin:{password}" "https://localhost:9200/wazuh-alerts-*/_mapping?pretty"'
    exit_code, stdout, stderr = run_remote_command(cmd, check=False)
    
    if exit_code == 0 and stdout:
        try:
            response = json.loads(stdout)
            # Get first index
            if response:
                first_index = list(response.keys())[0]
                print(f"   Checking index: {first_index}")
                
                mappings = response[first_index].get('mappings', {}).get('properties', {})
                gcp_fields = (mappings.get('data', {})
                             .get('properties', {})
                             .get('gcp', {})
                             .get('properties', {})
                             .get('jsonPayload', {})
                             .get('properties', {}))
                
                if gcp_fields:
                    print(f"✅ Found {len(gcp_fields)} GCP jsonPayload fields in index:")
                    for field_name, field_props in list(gcp_fields.items())[:10]:
                        field_type = field_props.get('type', 'unknown')
                        print(f"      - {field_name}: {field_type}")
                    if len(gcp_fields) > 10:
                        print(f"      ... and {len(gcp_fields) - 10} more")
                    return True
                else:
                    print("⚠️  No GCP fields found in current indices")
                    print("   Note: Template only applies to NEW indices")
                    return False
        except json.JSONDecodeError:
            print(f"⚠️  Could not parse mapping response")
            return False
    else:
        print(f"⚠️  Could not retrieve index mappings")
        return False


def cleanup_temp_files():
    """Clean up temporary files on remote"""
    print("\n🧹 Cleaning up temporary files...")
    run_remote_command('rm -f /tmp/gcp-index-template.json', check=False)
    print("✅ Cleanup complete")


def main():
    parser = argparse.ArgumentParser(
        description='Configure Wazuh index template for GCP security logs',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--password',
        help='Wazuh admin password (or set WAZUH_PASSWORD env var)',
        default=None
    )
    parser.add_argument(
        '--skip-health-check',
        action='store_true',
        help='Skip health check before applying template'
    )
    
    args = parser.parse_args()
    
    # Get password from args or environment
    import os
    password = args.password or os.environ.get('WAZUH_PASSWORD')
    
    if not password:
        print("❌ Error: Password required")
        print("\nUsage:")
        print("  python3 configure_index.py --password YOUR_PASSWORD")
        print("  or")
        print("  export WAZUH_PASSWORD='YOUR_PASSWORD'")
        print("  python3 configure_index.py")
        sys.exit(1)
    
    print("=" * 60)
    print("Wazuh Index Template Configuration")
    print("=" * 60)
    print()
    
    # Check SSH connection
    if not check_connection():
        print("\n❌ Cannot connect to Wazuh VM")
        print("   Make sure:")
        print("   - VM is running: gcloud compute instances list")
        print("   - You have SSH access: gcloud compute ssh wazuh-aio --zone us-central1-a --project apps-data-monitoring")
        sys.exit(1)
    
    # Check indexer health
    if not args.skip_health_check:
        if not check_indexer_health(password):
            print("\n⚠️  Wazuh indexer may not be ready")
            response = input("Continue anyway? (y/n): ")
            if response.lower() != 'y':
                sys.exit(1)
    
    # Create template
    if not create_index_template(password):
        cleanup_temp_files()
        print("\n❌ Failed to create index template")
        sys.exit(1)
    
    # Verify template
    time.sleep(2)  # Give indexer a moment
    if not verify_template(password):
        cleanup_temp_files()
        print("\n⚠️  Template creation uncertain")
        sys.exit(1)
    
    # Check current indices
    list_indexed_fields(password)
    
    # Cleanup
    cleanup_temp_files()
    
    print("\n" + "=" * 60)
    print("✅ Index Template Configuration Complete!")
    print("=" * 60)
    print()
    print("📝 Notes:")
    print("   - Template applies to NEW indices only")
    print("   - Existing indices are not affected")
    print("   - New data will be properly indexed")
    print()
    print("🔍 To verify fields are searchable:")
    print("   1. Generate some security events (run bruteforce test)")
    print("   2. Wait 2-3 minutes for Wazuh to process")
    print("   3. Search in Wazuh Dashboard:")
    print("      data.gcp.jsonPayload.result:\"failure\"")
    print()
    print("🗑️  To force reindex (loses old data):")
    print("   gcloud compute ssh wazuh-aio --zone us-central1-a --project apps-data-monitoring")
    print("   curl -k -u admin:PASSWORD -X DELETE https://localhost:9200/wazuh-alerts-*")
    print()


if __name__ == '__main__':
    main()

