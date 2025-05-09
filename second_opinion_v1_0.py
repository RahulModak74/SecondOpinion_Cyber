"""
Enhanced SecondOpinion with flexible embedding model support and dual vector stores

Usage:
python enhanced_second_opinion.py \
  --log_file log.txt \
  --incidents_store faiss_store \
  --chains_store faiss_store_chains \
  --openrouter_api_key your_openrouter_api_key \
  --output analysis_result.
  python3 second_opinion_v1_0.py --log_file splunklog.txt --incidents_store faiss_store --chains_store  faiss_store_chains --openrouter_api_key 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 --output  complete_op.csv

"""
import faiss
import numpy as np
import pandas as pd
import requests
import json
import os
import time
import torch
from typing import List, Dict, Any, Tuple, Optional

class EnhancedSecondOpinionAnalyzer:
    def __init__(self, 
                 incidents_store_path="faiss_store", 
                 chains_store_path="faiss_store_chains",
                 openrouter_api_key=None,
                 model_name="hkunlp/instructor-xl"):
        """
        Initialize the SecondOpinion analyzer with dual FAISS stores and flexible embedding models
        
        Args:
            incidents_store_path: Path to the incidents FAISS store directory
            chains_store_path: Path to the attack chains FAISS store directory
            openrouter_api_key: API key for OpenRouter
            model_name: Name of the embedding model to use
        """
        self.incidents_store_path = incidents_store_path
        self.chains_store_path = chains_store_path
        self.openrouter_api_key = openrouter_api_key
        
        # Load embedding model with fallbacks
        self.load_embedding_model(model_name)
        
        # Load FAISS indices
        self.load_incidents_index()
        self.load_chains_index()
    
    def load_embedding_model(self, model_name):
        """Load embedding model with fallbacks for compatibility"""
        print(f"Loading embedding model: {model_name}")
        
        # First try to load INSTRUCTOR model
        try:
            from InstructorEmbedding import INSTRUCTOR
            self.model = INSTRUCTOR(model_name)
            self.model_type = "instructor"
            self.dimension = 768  # INSTRUCTOR-XL dimension
            print("Successfully loaded INSTRUCTOR model")
        except Exception as e:
            print(f"Failed to load INSTRUCTOR model: {e}")
            print("Falling back to SentenceTransformer")
            
            # Fall back to SentenceTransformer
            try:
                from sentence_transformers import SentenceTransformer
                self.model_name = "all-mpnet-base-v2"  # Good alternative
                self.model = SentenceTransformer(self.model_name)
                self.model_type = "sentence_transformer"
                self.dimension = 768
                print(f"Successfully loaded SentenceTransformer model: {self.model_name}")
            except Exception as e2:
                raise RuntimeError(f"Failed to load embedding models: {e2}")
        
        # Move model to GPU if available
        if torch.cuda.is_available():
            self.model.to(torch.device("cuda"))
            print(f"Using GPU for embeddings: {torch.cuda.get_device_name(0)}")
        else:
            print("GPU not available, using CPU for embeddings")
        
    def load_incidents_index(self):
        """Load the incidents FAISS index and metadata from disk"""
        index_path = os.path.join(self.incidents_store_path, "incidents.index")
        if not os.path.exists(index_path):
            print(f"WARNING: Incidents FAISS index not found at {index_path}")
            self.incidents_index = None
            self.incidents_texts = []
            self.incidents_metadata = []
            self.incidents_instruction = "Represent this security event for threat detection"
            self.incidents_model_type = "sentence_transformer"
            return
        
        print(f"Loading incidents FAISS index from {index_path}")
        self.incidents_index = faiss.read_index(index_path)
        print(f"Incidents FAISS index loaded with {self.incidents_index.ntotal} vectors")
        
        # Load model info and instruction
        try:
            with open(os.path.join(self.incidents_store_path, "model_info.txt"), "r") as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith("Instruction:"):
                        self.incidents_instruction = line.split(":", 1)[1].strip()
                    elif line.startswith("Model Type:"):
                        self.incidents_model_type = line.split(":", 1)[1].strip()
                
                # Default if not found
                if not hasattr(self, 'incidents_instruction'):
                    self.incidents_instruction = "Represent this security event for threat detection"
                if not hasattr(self, 'incidents_model_type'):
                    self.incidents_model_type = "sentence_transformer"
        except:
            self.incidents_instruction = "Represent this security event for threat detection"
            self.incidents_model_type = "sentence_transformer"
        
        # Load texts and metadata
        import pickle
        try:
            with open(os.path.join(self.incidents_store_path, "texts.pkl"), "rb") as f:
                self.incidents_texts = pickle.load(f)
                
            with open(os.path.join(self.incidents_store_path, "metadata.pkl"), "rb") as f:
                self.incidents_metadata = pickle.load(f)
                
            print(f"Loaded {len(self.incidents_texts)} incident texts and metadata entries")
        except Exception as e:
            print(f"Error loading incidents metadata: {e}")
            self.incidents_texts = []
            self.incidents_metadata = []
    
    def load_chains_index(self):
        """Load the chains FAISS index and metadata from disk"""
        index_path = os.path.join(self.chains_store_path, "incidents.index")
        if not os.path.exists(index_path):
            print(f"WARNING: Chains FAISS index not found at {index_path}")
            self.chains_index = None
            self.chains_texts = []
            self.chains_metadata = []
            self.chains_instruction = "Represent this attack chain for security similarity matching"
            self.chains_model_type = "sentence_transformer"
            return
        
        print(f"Loading chains FAISS index from {index_path}")
        self.chains_index = faiss.read_index(index_path)
        print(f"Chains FAISS index loaded with {self.chains_index.ntotal} vectors")
        
        # Load model info and instruction
        try:
            with open(os.path.join(self.chains_store_path, "model_info.txt"), "r") as f:
                lines = f.readlines()
                for line in lines:
                    if line.startswith("Instruction:"):
                        self.chains_instruction = line.split(":", 1)[1].strip()
                    elif line.startswith("Model Type:"):
                        self.chains_model_type = line.split(":", 1)[1].strip()
                
                # Default if not found
                if not hasattr(self, 'chains_instruction'):
                    self.chains_instruction = "Represent this attack chain for security similarity matching"
                if not hasattr(self, 'chains_model_type'):
                    self.chains_model_type = "sentence_transformer"
        except:
            self.chains_instruction = "Represent this attack chain for security similarity matching"
            self.chains_model_type = "sentence_transformer"
        
        # Load texts and metadata
        import pickle
        try:
            with open(os.path.join(self.chains_store_path, "texts.pkl"), "rb") as f:
                self.chains_texts = pickle.load(f)
                
            with open(os.path.join(self.chains_store_path, "metadata.pkl"), "rb") as f:
                self.chains_metadata = pickle.load(f)
                
            print(f"Loaded {len(self.chains_texts)} chain texts and metadata entries")
        except Exception as e:
            print(f"Error loading chains metadata: {e}")
            self.chains_texts = []
            self.chains_metadata = []
    
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
    
    def embed_query(self, query_text: str, instruction: str, model_type: str = None) -> np.ndarray:
        """
        Embed a query text using the appropriate method based on model type
        
        Args:
            query_text: The query text to embed
            instruction: The instruction to use for INSTRUCTOR model
            model_type: The model type to use (defaults to self.model_type)
            
        Returns:
            Numpy array containing the embedding
        """
        if model_type is None:
            model_type = self.model_type
            
        try:
            if model_type == "instructor" and self.model_type == "instructor":
                # Use INSTRUCTOR model with instruction
                embedding = self.model.encode([[instruction, query_text]], convert_to_numpy=True)
            else:
                # Use SentenceTransformer with instruction prepended
                embedding = self.model.encode([f"{instruction}: {query_text}"], convert_to_numpy=True)
                
            # Normalize the embedding for cosine similarity
            faiss.normalize_L2(embedding)
            return embedding
        except Exception as e:
            print(f"Error creating embedding: {e}")
            # Return zeros as fallback
            return np.zeros((1, self.dimension), dtype=np.float32)
    
    def query_similar_incidents(self, query_text: str, k: int = 5) -> List[Dict[str, Any]]:
        """
        Query FAISS incidents index for similar incidents based on the query text
        
        Args:
            query_text: The query text
            k: Number of similar incidents to retrieve
            
        Returns:
            List of dictionaries containing similar incidents
        """
        if self.incidents_index is None:
            return []
        
        # Generate embedding for query
        query_embedding = self.embed_query(
            query_text, 
            self.incidents_instruction,
            self.incidents_model_type
        )
        
        # Search the index
        distances, indices = self.incidents_index.search(query_embedding, k)
        
        # Collect results
        results = []
        for i, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self.incidents_texts):  # Valid index
                results.append({
                    'text': self.incidents_texts[idx],
                    'metadata': self.incidents_metadata[idx],
                    'similarity_score': float(1 - distances[0][i])  # Convert distance to similarity
                })
        
        return results
    
    def query_similar_chains(self, query_text: str, k: int = 5) -> List[Dict[str, Any]]:
        """
        Query FAISS chains index for similar attack chains based on the query text
        
        Args:
            query_text: The query text
            k: Number of similar chains to retrieve
            
        Returns:
            List of dictionaries containing similar chains
        """
        if self.chains_index is None:
            return []
        
        # Generate embedding for query
        query_embedding = self.embed_query(
            query_text, 
            self.chains_instruction,
            self.chains_model_type
        )
        
        # Search the index
        distances, indices = self.chains_index.search(query_embedding, k)
        
        # Collect results
        results = []
        for i, idx in enumerate(indices[0]):
            if idx != -1 and idx < len(self.chains_texts):  # Valid index
                results.append({
                    'text': self.chains_texts[idx],
                    'metadata': self.chains_metadata[idx],
                    'similarity_score': float(1 - distances[0][i])  # Convert distance to similarity
                })
        
        return results
    
    def format_incident_for_llm(self, incident: Dict[str, Any]) -> str:
        """Format an incident for LLM prompt"""
        metadata = incident['metadata']
        formatted = f"Similar Incident (Score: {incident['similarity_score']:.2f}):\n"
        
        # Add metadata fields if they exist
        for key in ['Category', 'IncidentGrade', 'IncidentId', 'AlertId']:
            if key in metadata and metadata[key] is not None:
                formatted += f"{key}: {metadata[key]}\n"
        
        # Add timestamp if available
        if 'Timestamp' in metadata and metadata['Timestamp'] is not None:
            formatted += f"Time: {metadata['Timestamp']}\n"
        
        # Add the text representation
        formatted += f"Details: {incident['text']}\n"
        
        return formatted
    
    def format_chain_for_llm(self, chain: Dict[str, Any]) -> str:
        """Format a chain for LLM prompt"""
        metadata = chain['metadata']
        formatted = f"Similar Attack Chain (Score: {chain['similarity_score']:.2f}):\n"
        
        # Add metadata fields if they exist
        for key in ['chain_id', 'attack_name', 'severity', 'mitre_techniques']:
            if key in metadata and metadata[key] is not None:
                formatted += f"{key}: {metadata[key]}\n"
        
        # Add timeline if available
        if 'first_seen' in metadata and 'last_seen' in metadata:
            formatted += f"Timeline: {metadata.get('first_seen')} to {metadata.get('last_seen')}\n"
        
        if 'duration_hours' in metadata:
            formatted += f"Duration: {metadata.get('duration_hours')} hours\n"
        
        # Add chain stages if available
        if 'chain_stages' in metadata:
            formatted += f"Stages: {metadata.get('chain_stages')}\n"
        
        # Add the text representation
        formatted += f"Details: {chain['text']}\n"
        
        return formatted
    
    def get_rag_analysis(self, 
                         log_content: str, 
                         similar_incidents: List[Dict[str, Any]], 
                         similar_chains: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Get RAG analysis by querying OpenRouter with the log content, similar incidents, and similar chains
        
        Args:
            log_content: The log content
            similar_incidents: List of similar incidents from FAISS
            similar_chains: List of similar chains from FAISS
            
        Returns:
            Dictionary with analysis results
        """
        if not self.openrouter_api_key:
            return {
                "error": "OpenRouter API key not provided. Cannot perform LLM analysis."
            }
        
        # Format similar incidents and chains for the prompt
        incidents_context = ""
        if similar_incidents:
            incidents_context = "SIMILAR INDIVIDUAL SECURITY INCIDENTS IN OUR DATABASE:\n"
            incidents_context += "\n\n".join([self.format_incident_for_llm(incident) for incident in similar_incidents])
        
        chains_context = ""
        if similar_chains:
            chains_context = "SIMILAR ATTACK CHAIN PATTERNS IN OUR DATABASE:\n"
            chains_context += "\n\n".join([self.format_chain_for_llm(chain) for chain in similar_chains])
        
        # Create the prompt with both contexts
        prompt = f"""As a cybersecurity expert, analyze this security log and provide detailed insights based on our database of both individual security incidents and multi-stage attack chains.

LOG CONTENT:
{log_content[:3000]}  <!-- Truncated to avoid excessively long prompts -->

{incidents_context}

{chains_context}

Based on the provided log and the similar patterns in our database, please provide:

1. A comprehensive security assessment of what might be happening in the log, identifying specific suspicious activities, techniques, and potential attack stages.

2. Potential threats or concerns that should be investigated, including the possible intent and capability of the threat actor.

3. What this activity indicates based on historical patterns, including likely progression if this is part of a larger attack chain.

4. Recommended next steps for the security team, prioritized by urgency and impact, with specific mitigation strategies.

5. Confidence assessment: How confident are you in this analysis based on the quality of matches in our database?

Your response will serve as a "second opinion" to help security analysts contextualize and respond to this log effectively.
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
                    "model": "anthropic/claude-3-5-sonnet", # Using Claude 3.5 Sonnet for better security analysis
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
                    "similar_incidents": similar_incidents,
                    "similar_chains": similar_chains
                }
            else:
                return {
                    "error": f"OpenRouter API Error: {response.status_code} - {response.text}",
                    "similar_incidents": similar_incidents,
                    "similar_chains": similar_chains
                }
        
        except Exception as e:
            return {
                "error": f"Error calling OpenRouter API: {str(e)}",
                "similar_incidents": similar_incidents,
                "similar_chains": similar_chains
            }
    
    def analyze_log_file(self, 
                         log_file_path: str, 
                         incidents_k: int = 5, 
                         chains_k: int = 3) -> Dict[str, Any]:
        """
        Analyze a log file using both FAISS indices and OpenRouter
        
        Args:
            log_file_path: Path to the log file
            incidents_k: Number of similar incidents to retrieve
            chains_k: Number of similar chains to retrieve
            
        Returns:
            Dictionary with analysis results
        """
        # Parse the log file
        print(f"Parsing log file: {log_file_path}")
        log_content = self.parse_log_file(log_file_path)
        
        # Query similar incidents
        print("Querying similar incidents...")
        similar_incidents = self.query_similar_incidents(log_content, incidents_k)
        print(f"Found {len(similar_incidents)} similar incidents")
        
        # Query similar chains
        print("Querying similar attack chains...")
        similar_chains = self.query_similar_chains(log_content, chains_k)
        print(f"Found {len(similar_chains)} similar attack chains")
        
        # Get RAG analysis
        print("Getting comprehensive RAG analysis...")
        analysis_results = self.get_rag_analysis(log_content, similar_incidents, similar_chains)
        
        # Add log info to results
        analysis_results["log_file"] = log_file_path
        analysis_results["timestamp"] = time.strftime("%Y-%m-%d %H:%M:%S")
        analysis_results["num_similar_incidents"] = len(similar_incidents)
        analysis_results["num_similar_chains"] = len(similar_chains)
        
        return analysis_results


def main():
    import argparse
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Enhanced SecondOpinion Security Analyzer")
    parser.add_argument("--log_file", required=True, help="Path to the log file to analyze")
    parser.add_argument("--incidents_store", default="faiss_store", help="Path to the incidents FAISS store directory")
    parser.add_argument("--chains_store", default="faiss_store_chains", help="Path to the chains FAISS store directory")
    parser.add_argument("--openrouter_api_key", required=True, help="OpenRouter API key")
    parser.add_argument("--incidents_k", type=int, default=5, help="Number of similar incidents to retrieve")
    parser.add_argument("--chains_k", type=int, default=3, help="Number of similar chains to retrieve")
    parser.add_argument("--output", help="Path to save the analysis results")
    
    args = parser.parse_args()
    
    # Initialize the analyzer
    analyzer = EnhancedSecondOpinionAnalyzer(
        incidents_store_path=args.incidents_store,
        chains_store_path=args.chains_store,
        openrouter_api_key=args.openrouter_api_key
    )
    
    # Analyze the log file
    results = analyzer.analyze_log_file(
        args.log_file, 
        incidents_k=args.incidents_k,
        chains_k=args.chains_k
    )
    
    # Print or save the results
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"Analysis results saved to {args.output}")
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    # Print GPU information
    if torch.cuda.is_available():
        print(f"GPU available: {torch.cuda.get_device_name(0)}")
        print(f"GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.2f} GB")
    else:
        print("No GPU available, running on CPU")
    
    main()
