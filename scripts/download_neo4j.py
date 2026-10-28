import urllib.request
import zipfile
import os
import sys

def download_and_extract_neo4j():
    target_dir = os.path.join(os.path.dirname(__file__), "..", "neo4j-server")
    zip_path = os.path.join(os.path.dirname(__file__), "..", "neo4j.zip")
    url = "https://dist.neo4j.org/neo4j-community-5.20.0-windows.zip"
    
    if os.path.exists(target_dir):
        print("Neo4j directory already exists.")
        return

    print(f"Downloading Neo4j Community Server 5.20.0 from {url}...")
    urllib.request.urlretrieve(url, zip_path)
    
    print("Extracting Neo4j server archive...")
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(target_dir)
        
    if os.path.exists(zip_path):
        os.remove(zip_path)
        
    print(f"Neo4j extracted successfully to {target_dir}")

if __name__ == "__main__":
    download_and_extract_neo4j()
