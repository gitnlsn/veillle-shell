#!/usr/bin/env python3
"""
Path Orchestrator API
Provides multi-path verification through 40+ independent channels
"""

import subprocess
import asyncio
import hashlib
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, HttpUrl
import httpx
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI
app = FastAPI(
    title="Path Orchestrator API",
    description="Multi-path verification system",
    version="0.1.0"
)

# Models
class VerificationRequest(BaseModel):
    url: HttpUrl
    num_paths: int = 10
    timeout: int = 15

class PathResult(BaseModel):
    path_id: str
    chain: str
    success: bool
    data_hash: Optional[str] = None
    response_time_ms: Optional[int] = None
    error: Optional[str] = None

class VerificationResponse(BaseModel):
    url: str
    attack_detected: bool
    confidence: str
    attack_type: Optional[str] = None
    paths_checked: int
    paths_succeeded: int
    paths_agreed: int
    verified_data_hash: Optional[str] = None
    compromised_paths: List[str] = []
    safe_paths: List[str] = []
    results: List[PathResult] = []


class PathOrchestrator:
    """Orchestrates multi-path verification"""

    def __init__(self):
        self.namespaces = [f"vpn-ns-{i}" for i in range(10)]
        self.paths = self._generate_all_paths()
        logger.info(f"Initialized with {len(self.paths)} available paths")

    def _generate_all_paths(self) -> List[Dict]:
        """Generate all possible path combinations"""
        paths = []

        for i, ns in enumerate(self.namespaces):
            base_port_tor = 9050 + i
            base_port_http = 8080 + i

            # Path 1: VPN → Direct
            paths.append({
                'id': f'vpn-{i}-direct',
                'namespace': ns,
                'chain': f'VPN-{i} → Direct',
                'proxy': None,
            })

            # Path 2: VPN → Tor
            paths.append({
                'id': f'vpn-{i}-tor',
                'namespace': ns,
                'chain': f'VPN-{i} → Tor',
                'proxy': f'socks5h://127.0.0.1:{base_port_tor}',
            })

            # Path 3: VPN → HTTP Proxy (via Tor)
            paths.append({
                'id': f'vpn-{i}-http-proxy',
                'namespace': ns,
                'chain': f'VPN-{i} → HTTP-Proxy',
                'proxy': f'http://127.0.0.1:{base_port_http}',
            })

            # Path 4: VPN → Tor → HTTP Proxy
            paths.append({
                'id': f'vpn-{i}-tor-http',
                'namespace': ns,
                'chain': f'VPN-{i} → Tor → HTTP-Proxy',
                'proxy': f'socks5h://127.0.0.1:{base_port_tor}',
                'secondary_proxy': f'http://127.0.0.1:{base_port_http}',
            })

        return paths

    async def fetch_via_path(self, url: str, path: Dict, timeout: int) -> PathResult:
        """Fetch URL through specific path"""
        import time
        start_time = time.time()

        namespace = path['namespace']
        proxy = path.get('proxy')

        # Build command to execute in namespace
        cmd = ['ip', 'netns', 'exec', namespace, 'curl', '-s', '-L']

        # Add proxy if specified
        if proxy:
            cmd.extend(['--proxy', proxy])

        # Add timeouts
        cmd.extend(['--max-time', str(timeout)])

        # Add URL
        cmd.append(str(url))

        try:
            result = await asyncio.wait_for(
                asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                ),
                timeout=timeout + 5
            )

            stdout, stderr = await result.communicate()

            elapsed_ms = int((time.time() - start_time) * 1000)

            if result.returncode == 0:
                data = stdout.decode('utf-8')
                data_hash = hashlib.sha256(data.encode()).hexdigest()[:16]

                return PathResult(
                    path_id=path['id'],
                    chain=path['chain'],
                    success=True,
                    data_hash=data_hash,
                    response_time_ms=elapsed_ms
                )
            else:
                return PathResult(
                    path_id=path['id'],
                    chain=path['chain'],
                    success=False,
                    error=stderr.decode('utf-8')[:200]
                )

        except asyncio.TimeoutError:
            return PathResult(
                path_id=path['id'],
                chain=path['chain'],
                success=False,
                error='TIMEOUT'
            )
        except Exception as e:
            return PathResult(
                path_id=path['id'],
                chain=path['chain'],
                success=False,
                error=str(e)[:200]
            )

    async def verify_multi_path(
        self,
        url: str,
        num_paths: int = 10,
        timeout: int = 15
    ) -> VerificationResponse:
        """Verify URL through multiple paths"""

        logger.info(f"Starting multi-path verification for {url}")
        logger.info(f"Using {num_paths} paths with {timeout}s timeout")

        # Select paths
        import random
        selected_paths = random.sample(self.paths, min(num_paths, len(self.paths)))

        # Fetch through all paths concurrently
        tasks = [
            self.fetch_via_path(url, path, timeout)
            for path in selected_paths
        ]

        results = await asyncio.gather(*tasks)

        # Analyze results
        return self._analyze_results(url, results)

    def _analyze_results(self, url: str, results: List[PathResult]) -> VerificationResponse:
        """Compare results from all paths to detect attacks"""

        successful = [r for r in results if r.success]

        if len(successful) < 3:
            logger.warning(f"Only {len(successful)} successful paths - low confidence")
            return VerificationResponse(
                url=str(url),
                attack_detected=False,
                confidence='LOW',
                paths_checked=len(results),
                paths_succeeded=len(successful),
                paths_agreed=0,
                results=results
            )

        # Group by data hash
        hash_groups: Dict[str, List[PathResult]] = {}
        for result in successful:
            h = result.data_hash
            if h not in hash_groups:
                hash_groups[h] = []
            hash_groups[h].append(result)

        if len(hash_groups) == 1:
            # All paths returned same data - likely legitimate
            logger.info(f"All {len(successful)} paths agreed - no attack detected")

            return VerificationResponse(
                url=str(url),
                attack_detected=False,
                confidence='HIGH',
                paths_checked=len(results),
                paths_succeeded=len(successful),
                paths_agreed=len(successful),
                verified_data_hash=successful[0].data_hash,
                safe_paths=[r.path_id for r in successful],
                results=results
            )
        else:
            # Different responses - ATTACK DETECTED!
            logger.warning(f"ATTACK DETECTED: {len(hash_groups)} different responses!")

            # Majority vote
            sorted_groups = sorted(hash_groups.items(), key=lambda x: len(x[1]), reverse=True)
            majority_hash, majority_paths = sorted_groups[0]

            minority_paths = [
                path
                for h, paths in sorted_groups[1:]
                for path in paths
            ]

            confidence = 'HIGH' if len(majority_paths) >= len(successful) * 0.7 else 'MEDIUM'

            return VerificationResponse(
                url=str(url),
                attack_detected=True,
                confidence=confidence,
                attack_type='MITM_SUSPECTED',
                paths_checked=len(results),
                paths_succeeded=len(successful),
                paths_agreed=len(majority_paths),
                verified_data_hash=majority_hash,
                compromised_paths=[p.path_id for p in minority_paths],
                safe_paths=[p.path_id for p in majority_paths],
                results=results
            )


# Global orchestrator instance
orchestrator = PathOrchestrator()

# API Endpoints

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "available_paths": len(orchestrator.paths),
        "namespaces": len(orchestrator.namespaces)
    }

@app.post("/verify", response_model=VerificationResponse)
async def verify_url(request: VerificationRequest):
    """
    Verify URL through multiple independent paths

    This endpoint performs multi-path verification to detect MITM attacks
    by comparing responses from different network paths.
    """

    try:
        result = await orchestrator.verify_multi_path(
            url=str(request.url),
            num_paths=request.num_paths,
            timeout=request.timeout
        )
        return result

    except Exception as e:
        logger.error(f"Verification error: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/paths")
async def list_paths():
    """List all available verification paths"""
    return {
        "total_paths": len(orchestrator.paths),
        "namespaces": len(orchestrator.namespaces),
        "paths": [
            {
                "id": p['id'],
                "chain": p['chain']
            }
            for p in orchestrator.paths
        ]
    }


if __name__ == "__main__":
    import uvicorn

    logger.info("Starting Path Orchestrator API on port 8000")

    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8000,
        log_level="info"
    )
