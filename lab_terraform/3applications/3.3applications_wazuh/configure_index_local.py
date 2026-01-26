#!/usr/bin/env python3
"""
Configure Wazuh Index Template for GCP Security Logs (VM Local Version)

This script is designed to run DIRECTLY on the Wazuh VM.
For remote execution, use configure_index.py instead.

Usage:
    python3 configure_index_local.py --password YOUR_ADMIN_PASSWORD
"""

import argparse
import json
import subprocess
import sys
import time
from typing import Tuple


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


def run_command(command: str, check: bool = True, shell: bool = True) -> Tuple[int, str, str]:
    """Execute a local command"""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=check,
            shell=shell
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        return e.returncode, e.stdout, e.stderr


def check_indexer_health(password: str) -> bool:
    """Check if Wazuh indexer is healthy"""
    print("🔍 Checking Wazuh indexer health...")
    
    command = f'curl -s -k -u "admin:{password}" https://localhost:9200/_cluster/health'
    exit_code, stdout, stderr = run_command(command, check=False)
    
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
    
    # Save template to temp file
    template_json = json.dumps(INDEX_TEMPLATE, indent=2)
    
    with open('/tmp/gcp-index-template.json', 'w') as f:
        f.write(template_json)
    
    print("✅ Template file created")
    
    # Apply the template
    print("📤 Applying index template to Wazuh indexer...")
    apply_cmd = f'''curl -s -k -w "\\n%{{http_code}}" \
        -X PUT "https://localhost:9200/_index_template/gcp-security-fields" \
        -u "admin:{password}" \
        -H 'Content-Type: application/json' \
        -d @/tmp/gcp-index-template.json'''
    
    exit_code, stdout, stderr = run_command(apply_cmd, check=False)
    
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
    exit_code, stdout, stderr = run_command(verify_cmd, check=False)
    
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


def main():
    parser = argparse.ArgumentParser(
        description='Configure Wazuh index template for GCP security logs (VM local version)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        '--password',
        required=True,
        help='Wazuh admin password'
    )
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Wazuh Index Template Configuration (VM Local)")
    print("=" * 60)
    print()
    
    # Check indexer health
    if not check_indexer_health(args.password):
        print("\n⚠️  Wazuh indexer may not be ready")
        sys.exit(1)
    
    # Create template
    if not create_index_template(args.password):
        print("\n❌ Failed to create index template")
        sys.exit(1)
    
    # Verify template
    time.sleep(2)
    if not verify_template(args.password):
        print("\n⚠️  Template creation uncertain")
        sys.exit(1)
    
    print("\n" + "=" * 60)
    print("✅ Index Template Configuration Complete!")
    print("=" * 60)


if __name__ == '__main__':
    main()

