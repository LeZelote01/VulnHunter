import requests
import threading
import time
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class CVESearcher:
    def __init__(self):
        self.circl_url = "https://cve.circl.lu/api/search"
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
        self.api_key = os.getenv("NVD_API_KEY")
        self.session = self._create_session()
        self.lock = threading.Lock()
        self.delay = 0.6  # Respect NVD rate limits (5 requests/3s)

    def _create_session(self):
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session

    def _search_circl(self, product, version):
        params = {"product": product, "version": version}
        try:
            response = self.session.get(self.circl_url, params=params, timeout=10)
            return response.json() if response.status_code == 200 else []
        except Exception:
            return []

    def _search_nvd(self, product, version):
        params = {
            "keyword": f"{product} {version}",
            "resultsPerPage": 20
        }
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            with self.lock:
                time.sleep(self.delay)
                response = self.session.get(
                    self.nvd_url,
                    params=params,
                    headers=headers,
                    timeout=15
                )
            
            if response.status_code != 200:
                return []
            
            data = response.json()
            return self._parse_nvd(data)
        except Exception:
            return []

    def _parse_nvd(self, data):
        vulnerabilities = []
        for item in data.get("result", {}).get("CVE_Items", []):
            cve = item["cve"]
            metrics = cve["metrics"]
            
            # Get highest CVSS score
            cvss_score = 0.0
            for metric_type in metrics:
                for metric in metrics[metric_type]:
                    if "baseScore" in metric:
                        cvss_score = max(cvss_score, metric["baseScore"])
            
            vulnerabilities.append({
                "id": cve["CVE_data_meta"]["ID"],
                "summary": cve["description"]["description_data"][0]["value"],
                "cvss": cvss_score,
                "source": "NVD"
            })
        return vulnerabilities

    def search(self, product, version):
        results = []
        
        # Recherche dans CIRCL
        circl_results = self._search_circl(product, version)
        if circl_results:
            results.extend({
                "id": cve["id"],
                "summary": cve["summary"][:500],
                "cvss": float(cve.get("cvss", 0)),
                "source": "CIRCL"
            } for cve in circl_results)
        
        # Recherche dans NVD
        nvd_results = self._search_nvd(product, version)
        results.extend(nvd_results)
        
        # Éliminer les doublons et trier par CVSS
        seen = set()
        unique_results = []
        for res in results:
            if res["id"] not in seen:
                seen.add(res["id"])
                unique_results.append(res)
        
        return sorted(unique_results, key=lambda x: x["cvss"], reverse=True)[:15]