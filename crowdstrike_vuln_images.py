import requests
import json
import time
import csv
from typing import List, Dict, Optional

class CrowdStrikeVulnAnalyzer:
    def __init__(self, base_url: str, client_id: str, client_secret: str):
        self.base_url = base_url.rstrip('/')
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.token_expires_at = 0
        self._authenticate()
    
    def _authenticate(self) -> bool:
        url = f"{self.base_url}/oauth2/token"
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        data = {
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'grant_type': 'client_credentials'
        }
        
        try:
            response = requests.post(url, headers=headers, data=data)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data.get('access_token')
            expires_in = token_data.get('expires_in', 3600)
            self.token_expires_at = time.time() + expires_in - 300
            print("✓ Authentication successful")
            return True
        except Exception as e:
            print(f"✗ Authentication failed: {e}")
            return False
    
    def _get_headers(self) -> Dict[str, str]:
        if time.time() >= self.token_expires_at:
            self._authenticate()
        return {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
    
    def get_all_vulnerabilities_fixed(self, additional_filters: Optional[str] = None) -> List[Dict]:
        """Get ALL vulnerabilities using proper pagination"""
        all_vulnerabilities = []
        offset = 0
        limit = 100  # API maximum
        batch_number = 0
        total_from_api = None
        
        print("="*60)
        print("FETCHING ALL VULNERABILITIES")
        print("="*60)
        
        url = f"{self.base_url}/container-security/combined/vulnerabilities/v1"
        
        try:
            # First try to get the total count
            params = {'limit': 1, 'offset': 0}
            if additional_filters:
                params['filter'] = additional_filters
            
            response = requests.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()
            
            data = response.json()
            meta = data.get('meta', {})
            pagination = meta.get('pagination', {})
            total_from_api = pagination.get('total', 0)
            
            if total_from_api == 0:
                print("No vulnerabilities found in the system")
                return []
            
            print(f"🎯 Total vulnerabilities available: {total_from_api:,}")
            
            # Now fetch all vulnerabilities
            while True:
                batch_number += 1
                print(f"Batch {batch_number}: offset={offset}, limit={limit}")
                
                params = {'limit': limit, 'offset': offset}
                if additional_filters:
                    params['filter'] = additional_filters
                
                response = requests.get(url, headers=self._get_headers(), params=params)
                
                # Handle different response codes
                if response.status_code == 500:
                    print(f"⚠️ Server Error 500 for batch {batch_number} - retrying with smaller batch")
                    limit = max(10, limit // 2)  # Reduce batch size but not smaller than 10
                    continue
                
                response.raise_for_status()
                data = response.json()
                
                batch_resources = data.get('resources', [])
                batch_size = len(batch_resources)
                
                if batch_size == 0:
                    print("📭 Empty batch - reached end")
                    break
                
                all_vulnerabilities.extend(batch_resources)
                print(f"✅ Added {batch_size} vulnerabilities (total: {len(all_vulnerabilities):,})")
                
                if len(all_vulnerabilities) >= total_from_api:
                    print(f"🎉 Collected all {total_from_api:,} vulnerabilities!")
                    break
                
                offset += batch_size  # Use actual batch size instead of limit
                time.sleep(0.2)  # Slightly longer delay between batches
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Error fetching vulnerabilities: {e}")
            if not all_vulnerabilities:
                raise  # Only raise if we haven't collected any vulnerabilities
        
        print(f"✅ Fetching complete: {len(all_vulnerabilities):,} vulnerabilities collected")
        return all_vulnerabilities

    def get_images_for_cve(self, cve_id: str) -> List[Dict]:
        """Get detailed information about all images affected by a CVE"""
        url = f"{self.base_url}/container-security/combined/image-assessment/images/v1"
        filter_string = f"cve_id:'{cve_id}'"
        all_images = []
        offset = 0
        limit = 100

        while True:
            params = {
                'filter': filter_string,
                'limit': limit,
                'offset': offset
            }

            try:
                response = requests.get(url, headers=self._get_headers(), params=params)
                
                # Check for specific error codes
                if response.status_code == 404:
                    print(f"⚠️  No images found for {cve_id}")
                    break
                
                response.raise_for_status()
                data = response.json()
                
                batch_resources = data.get('resources', [])
                if not batch_resources:
                    break

                all_images.extend(batch_resources)
                
                # Check if we've received fewer items than the limit
                if len(batch_resources) < limit:
                    break

                offset += limit
                time.sleep(0.1)  # Rate limiting

            except requests.exceptions.RequestException as e:
                if "404" in str(e):
                    print(f"⚠️  No images found for {cve_id}")
                else:
                    print(f"❌ Error fetching images for {cve_id}: {e}")
                break
            except Exception as e:
                print(f"❌ Unexpected error processing {cve_id}: {e}")
                break

        return all_images

    def analyze_vulnerabilities_working(self, vuln_filters: Optional[str] = None) -> List[Dict]:
        """Simplified analysis function focusing only on CVEs and impacted images"""
        print("="*80)
        print("🚀 CROWDSTRIKE VULNERABILITY ANALYZER")
        print("="*80)
        
        # Fetch all vulnerabilities
        vulnerabilities = self.get_all_vulnerabilities_fixed(additional_filters=vuln_filters)
        
        if not vulnerabilities:
            print("❌ No vulnerabilities found")
            return []
        
        print(f"✅ Collected {len(vulnerabilities):,} vulnerabilities")
        
        results = []
        processed_count = 0
        total_vulns = len(vulnerabilities)
        
        for vuln in vulnerabilities:
            processed_count += 1
            cve_id = vuln.get('cve_id')
            if not cve_id:
                continue
                
            # Show progress percentage
            progress = (processed_count / total_vulns) * 100
            print(f"Processing {cve_id}... ({progress:.1f}% complete)")
            
            # Get all impacted images for this CVE
            impacted_images = self.get_images_for_cve(cve_id)
            
            # Only add to results if there are impacted images
            if impacted_images:
                result = {
                    'cve_id': cve_id,
                    'severity': vuln.get('severity'),
                    'cvss_score': vuln.get('cvss_score'),
                    'description': vuln.get('description', ''),
                    'published_date': vuln.get('published_date'),
                    'impacted_images': [{
                        'registry': img.get('registry', ''),
                        'repository': img.get('repository', ''),
                        'tag': img.get('tag', '')
                    } for img in impacted_images]
                }
                
                results.append(result)
                print(f"✅ Found {len(impacted_images)} impacted images for {cve_id}")
            
        return results

def convert_to_csv(results: List[Dict], timestamp: str) -> None:
    """Convert results to CSV format"""
    csv_filename = f'vulnerability_analysis_{timestamp}.csv'
    
    # Flatten the data structure for CSV
    csv_rows = []
    for vuln in results:
        for image in vuln['impacted_images']:
            row = {
                'cve_id': vuln['cve_id'],
                'severity': vuln['severity'],
                'cvss_score': vuln['cvss_score'],
                'published_date': vuln['published_date'],
                'registry': image['registry'],
                'repository': image['repository'],
                'tag': image['tag']
            }
            csv_rows.append(row)
    
    # Write to CSV
    if csv_rows:
        with open(csv_filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=csv_rows[0].keys())
            writer.writeheader()
            writer.writerows(csv_rows)
        print(f"📝 CSV report saved to: {csv_filename}")

def main():
    # Configuration
    BASE_URL = "https://api.crowdstrike.com"
    CLIENT_ID = "your_client_id_here"
    CLIENT_SECRET = "your_client_secret_here"
    
    try:
        start_time = time.time()
        analyzer = CrowdStrikeVulnAnalyzer(BASE_URL, CLIENT_ID, CLIENT_SECRET)
        
        # Run analysis
        results = analyzer.analyze_vulnerabilities_working()
        
        if not results:
            print("No results to display")
            return
        
        # Generate timestamp for filenames
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        
        # Save JSON results
        json_filename = f'vulnerability_analysis_{timestamp}.json'
        with open(json_filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 JSON report saved to: {json_filename}")
        
        # Save CSV results
        convert_to_csv(results, timestamp)
        
        # Calculate execution time
        execution_time = time.time() - start_time
        
        # Display summary of findings
        total_images = sum(len(r['impacted_images']) for r in results)
        print(f"\n📊 Summary:")
        print(f"   - Total CVEs with impacted images: {len(results):,}")
        print(f"   - Total impacted images: {total_images:,}")
        print(f"   - Execution time: {execution_time:.2f} seconds")
        
    except Exception as e:
        print(f"❌ Script failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()
