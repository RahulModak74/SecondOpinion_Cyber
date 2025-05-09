"""
python second_opinion.py \
  --log_file log.csv \
  --faiss_store old_faiss_store \
  --openrouter_api_key your_openrouter_api_key \
  --output analysis_result.json
"""
import faiss
import numpy as np
import pandas as pd
import requests
import json
import os
import time
from sentence_transformers import SentenceTransformer
from typing import List, Dict, Any

class SecondOpinionAnalyzer:
    def __init__(self, 
                 faiss_store_path="old_faiss_store", 
                 openrouter_api_key=None,
                 model_name="all-MiniLM-L6-v2"):
        """
        Initialize the SecondOpinion analyzer with FAISS store and OpenRouter API key
        
        Args:
            faiss_store_path: Path to the FAISS store directory
            openrouter_api_key: API key for OpenRouter
            model_name: Name of the SentenceTransformer model to use
        """
        self.faiss_store_path = faiss_store_path
        self.openrouter_api_key = openrouter_api_key
        
        # Load embedding model
        print(f"Loading embedding model: {model_name}")
        self.model = SentenceTransformer(model_name)
        self.dimension = self.model.get_sentence_embedding_dimension()
        
        # Load FAISS index
        self.load_faiss_index()
        
        # Load metadata
        self.load_metadata()
        
    def load_faiss_index(self):
        """Load the FAISS index from disk"""
        index_path = os.path.join(self.faiss_store_path, "incidents.index")
        if not os.path.exists(index_path):
            raise FileNotFoundError(f"FAISS index not found at {index_path}")
        
        print(f"Loading FAISS index from {index_path}")
        self.index = faiss.read_index(index_path)
        print(f"FAISS index loaded with {self.index.ntotal} vectors of dimension {self.dimension}")
        
    def load_metadata(self):
        """Load the metadata for the stored vectors"""
        texts_path = os.path.join(self.faiss_store_path, "texts.pkl")
        metadata_path = os.path.join(self.faiss_store_path, "metadata.pkl")
        
        if not os.path.exists(texts_path) or not os.path.exists(metadata_path):
            raise FileNotFoundError(f"Metadata files not found at {texts_path} or {metadata_path}")
        
        import pickle
        print(f"Loading metadata from {self.faiss_store_path}")
        
        with open(texts_path, "rb") as f:
            self.texts = pickle.load(f)
            
        with open(metadata_path, "rb") as f:
            self.metadata = pickle.load(f)
            
        print(f"Loaded {len(self.texts)} texts and {len(self.metadata)} metadata entries")
        
    def parse_log_file(self, log_file_path: str) -> str:
        """
        Parse a log file and return a formatted string representation
        
        Args:
            log_file_path: Path to the log file (CSV or plain text)
            
        Returns:
            Formatted string representation of the log
        """
        # Check file extension
        _, ext = os.path.splitext(log_file_path)
        
        if ext.lower() == '.csv':
            # Parse CSV file
            try:
                df = pd.read_csv(log_file_path)
                # Extract key columns and create a formatted string
                log_content = "CSV Log Summary:\n"
                
                # Add column names
                log_content += f"Columns: {', '.join(df.columns)}\n\n"
                
                # Add sample rows
                max_rows = min(5, len(df))
                for i in range(max_rows):
                    log_content += f"Row {i+1}:\n"
                    for col in df.columns:
                        log_content += f"  {col}: {df.iloc[i][col]}\n"
                    log_content += "\n"
                
                # Add summary statistics for numeric columns
                log_content += "Summary Statistics:\n"
                for col in df.select_dtypes(include=np.number).columns:
                    log_content += f"  {col}: min={df[col].min()}, max={df[col].max()}, mean={df[col].mean():.2f}\n"
                
                return log_content
            
            except Exception as e:
                print(f"Error parsing CSV file: {e}")
                # Fall back to treating it as a text file
                pass
        
        # Parse as plain text file
        try:
            with open(log_file_path, 'r', encoding='utf-8') as f:
                log_lines = f.readlines()
            
            # If the file is very large, truncate it
            if len(log_lines) > 100:
                log_content = "".join(log_lines[:50])
                log_content += f"\n\n[...{len(log_lines)-100} lines omitted...]\n\n"
                log_content += "".join(log_lines[-50:])
            else:
                log_content = "".join(log_lines)
                
            return log_content
        
        except Exception as e:
            raise Exception(f"Failed to parse log file: {e}")
    
    def query_similar_chains(self, query_text: str, k: int = 5) -> List[Dict[str, Any]]:
        """
        Query FAISS for similar chains based on the query text
        
        Args:
            query_text: The query text
            k: Number of similar chains to retrieve
            
        Returns:
            List of dictionaries containing similar chains
        """
        # Generate embedding for query
        query_embedding = self.model.encode([query_text], convert_to_numpy=True)
        
        # Normalize the query embedding for cosine similarity
        faiss.normalize_L2(query_embedding)
        
        # Search the index
        distances, indices = self.index.search(query_embedding, k)
        
        # Collect results
        results = []
        for i, idx in enumerate(indices[0]):
            if idx != -1:  # Valid index
                results.append({
                    'text': self.texts[idx],
                    'metadata': self.metadata[idx],
                    'similarity_score': float(1 - distances[0][i])  # Convert distance to similarity
                })
        
        return results
    
    def format_chain_for_llm(self, chain: Dict[str, Any]) -> str:
        """Format a chain for LLM prompt"""
        metadata = chain['metadata']
        formatted = f"Attack Chain (Similarity: {chain['similarity_score']:.2f}):\n"
        formatted += f"Category: {metadata.get('Category', 'Unknown')}\n"
        formatted += f"Grade: {metadata.get('IncidentGrade', 'Unknown')}\n"
        formatted += f"Details: {chain['text']}\n"
        
        return formatted
    
    def get_rag_analysis(self, log_content: str, similar_chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get RAG analysis by querying OpenRouter with the log content and similar chains
        
        Args:
            log_content: The log content
            similar_chains: List of similar chains from FAISS
            
        Returns:
            Dictionary with analysis results
        """
        if not self.openrouter_api_key:
            return {
                "error": "OpenRouter API key not provided. Cannot perform LLM analysis."
            }
        
        # Format similar chains for the prompt
        chains_context = "\n\n".join([self.format_chain_for_llm(chain) for chain in similar_chains])
        
        # Create the prompt
        prompt = f"""As a cybersecurity expert, analyze this security log and provide insights based on similar attack patterns we've observed.

LOG CONTENT:
{log_content[:3000]}  <!-- Truncated to avoid excessively long prompts -->

SIMILAR ATTACK PATTERNS IN OUR DATABASE:
{chains_context}

Based on these similar attack patterns, please provide:
1. A security assessment of what might be happening in the log
2. Potential threats or concerns that should be investigated
3. What this activity might indicate based on historical patterns
4. Recommended next steps for the security team

Your response will serve as a "second opinion" to help security analysts contextualize this log.
"""
        
        # Call OpenRouter API
        try:
            response = requests.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.openrouter_api_key}",
                    "Content-Type": "application/json",
                    "HTTP-Referer": "https://secondopinion.security"  # Replace with your domain
                },
                json={
                    "model": "deepseek/deepseek-chat:free", # You can change this to your preferred model
                    "messages": [
                        {"role": "user", "content": prompt}
                    ]
                }
            )
            
            # Check if the request was successful
            if response.status_code == 200:
                llm_response = response.json()["choices"][0]["message"]["content"]
                return {
                    "analysis": llm_response,
                    "similar_chains": similar_chains
                }
            else:
                return {
                    "error": f"OpenRouter API Error: {response.status_code} - {response.text}",
                    "similar_chains": similar_chains
                }
        
        except Exception as e:
            return {
                "error": f"Error calling OpenRouter API: {str(e)}",
                "similar_chains": similar_chains
            }
    
    def analyze_log_file(self, log_file_path: str, k: int = 5) -> Dict[str, Any]:
        """
        Analyze a log file using FAISS and OpenRouter
        
        Args:
            log_file_path: Path to the log file
            k: Number of similar chains to retrieve
            
        Returns:
            Dictionary with analysis results
        """
        # Parse the log file
        print(f"Parsing log file: {log_file_path}")
        log_content = self.parse_log_file(log_file_path)
        
        # Query similar chains
        print("Querying similar chains...")
        similar_chains = self.query_similar_chains(log_content, k)
        
        # Get RAG analysis
        print("Getting RAG analysis...")
        analysis_results = self.get_rag_analysis(log_content, similar_chains)
        
        # Add log info to results
        analysis_results["log_file"] = log_file_path
        analysis_results["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        
        return analysis_results

# Example usage
if __name__ == "__main__":
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="SecondOpinion Security Analyzer")
    parser.add_argument("--log_file", required=True, help="Path to the log file to analyze")
    parser.add_argument("--faiss_store", default="old_faiss_store", help="Path to the FAISS store directory")
    parser.add_argument("--openrouter_api_key", required=True, help="OpenRouter API key")
    parser.add_argument("--k", type=int, default=5, help="Number of similar chains to retrieve")
    parser.add_argument("--output", help="Path to save the analysis results")
    
    args = parser.parse_args()
    
    # Initialize the analyzer
    analyzer = SecondOpinionAnalyzer(
        faiss_store_path=args.faiss_store,
        openrouter_api_key=args.openrouter_api_key
    )
    
    # Analyze the log file
    results = analyzer.analyze_log_file(args.log_file, args.k)
    
    # Print or save the results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Analysis results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))
