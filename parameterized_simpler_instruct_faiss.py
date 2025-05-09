import pandas as pd
import numpy as np
import faiss
import os
import torch
import argparse
from InstructorEmbedding import INSTRUCTOR
from sentence_transformers import SentenceTransformer
import pickle
import gc
from tqdm import tqdm
"""
pip3 uninstall InstructorEmbedding
pip3 install InstructorEmbedding==1.0.0
"""
class EnhancedFAISSVectorStore:
    def __init__(self, model_name="hkunlp/instructor-xl", dimension=768, use_instructor=True):
        """
        Initialize the FAISS vector store with INSTRUCTOR embedding model.
        Falls back to SentenceTransformer if INSTRUCTOR fails.
        
        Args:
            model_name: The embedding model to use
            dimension: The dimension of the embedding vectors
            use_instructor: Whether to try using INSTRUCTOR model first
        """
        self.model_name = model_name
        self.dimension = dimension
        self.use_instructor = use_instructor
        self.texts = []
        self.metadata = []
        
        # Load embedding model - try INSTRUCTOR first, fallback to SentenceTransformer
        print(f"Loading embedding model: {model_name}")
        if use_instructor:
            try:
                self.embedding_model = INSTRUCTOR(model_name)
                self.model_type = "instructor"
                print("Successfully loaded INSTRUCTOR model")
            except Exception as e:
                print(f"Failed to load INSTRUCTOR model: {e}")
                print("Falling back to SentenceTransformer")
                self.model_name = "all-mpnet-base-v2"  # Good alternative
                self.dimension = 768
                self.embedding_model = SentenceTransformer(self.model_name)
                self.model_type = "sentence_transformer"
        else:
            self.embedding_model = SentenceTransformer(model_name)
            self.model_type = "sentence_transformer"
            
        # Move model to GPU if available
        if torch.cuda.is_available():
            self.embedding_model.to(torch.device("cuda"))
            print(f"Using GPU for embeddings: {torch.cuda.get_device_name(0)}")
        else:
            print("GPU not available, using CPU for embeddings")
            
        self.index = None
        self.instruction = "Represent this security event for threat detection"
        
    def _create_text_for_embedding(self, row):
        """Create a text representation from a row of the dataframe for embedding"""
        text_parts = []
        
        # Add incident information
        if pd.notna(row.get('AlertTitle')):
            text_parts.append(f"Alert: {row['AlertTitle']}")
        if pd.notna(row.get('Category')):
            text_parts.append(f"Category: {row['Category']}")
        if pd.notna(row.get('MitreTechniques')):
            text_parts.append(f"MITRE Techniques: {row['MitreTechniques']}")
        if pd.notna(row.get('IncidentGrade')):
            text_parts.append(f"Incident Grade: {row['IncidentGrade']}")
        
        # Add action information
        if pd.notna(row.get('ActionGrouped')):
            text_parts.append(f"Action: {row['ActionGrouped']}")
        if pd.notna(row.get('ActionGranular')):
            text_parts.append(f"Specific Action: {row['ActionGranular']}")
        
        # Add entity information
        if pd.notna(row.get('EntityType')):
            text_parts.append(f"Entity Type: {row['EntityType']}")
        if pd.notna(row.get('EvidenceRole')):
            text_parts.append(f"Evidence Role: {row['EvidenceRole']}")
        
        # Add threat information if available
        if pd.notna(row.get('ThreatFamily')):
            text_parts.append(f"Threat Family: {row['ThreatFamily']}")
        
        # Add resource information
        if pd.notna(row.get('ResourceType')):
            text_parts.append(f"Resource Type: {row['ResourceType']}")
        if pd.notna(row.get('Roles')):
            text_parts.append(f"Roles: {row['Roles']}")
        
        # Add verdict information
        if pd.notna(row.get('SuspicionLevel')):
            text_parts.append(f"Suspicion Level: {row['SuspicionLevel']}")
        if pd.notna(row.get('LastVerdict')):
            text_parts.append(f"Verdict: {row['LastVerdict']}")
        
        return " | ".join(text_parts)
    
    def _create_text_for_chain_embedding(self, row):
        """Create a text representation from a row of the attack chain dataframe"""
        text_parts = []
        
        # Add chain information
        if pd.notna(row.get('chain_id')):
            text_parts.append(f"Chain ID: {row['chain_id']}")
        if pd.notna(row.get('attack_name')):
            text_parts.append(f"Attack: {row['attack_name']}")
        if pd.notna(row.get('attack_description')):
            text_parts.append(f"Description: {row['attack_description']}")
        
        # Add MITRE framework information
        if pd.notna(row.get('mitre_tactics')):
            text_parts.append(f"Tactics: {row['mitre_tactics']}")
        if pd.notna(row.get('mitre_techniques')):
            text_parts.append(f"Techniques: {row['mitre_techniques']}")
        
        # Add severity and timeline
        if pd.notna(row.get('severity')):
            text_parts.append(f"Severity: {row['severity']}")
        if pd.notna(row.get('first_seen')) and pd.notna(row.get('last_seen')):
            text_parts.append(f"Timeline: {row['first_seen']} to {row['last_seen']}")
        if pd.notna(row.get('duration_hours')):
            text_parts.append(f"Duration: {row['duration_hours']} hours")
        
        # Add affected entities
        if pd.notna(row.get('affected_hosts')):
            text_parts.append(f"Hosts: {row['affected_hosts']}")
        if pd.notna(row.get('affected_users')):
            text_parts.append(f"Users: {row['affected_users']}")
        
        # Add chain stages and descriptions
        if pd.notna(row.get('chain_stages')):
            text_parts.append(f"Stages: {row['chain_stages']}")
        if pd.notna(row.get('stage_descriptions')):
            text_parts.append(f"Stage Details: {row['stage_descriptions']}")
        
        # Add events summary
        if pd.notna(row.get('events_summary')):
            text_parts.append(f"Events: {row['events_summary']}")
        
        # Add IOCs
        iocs = []
        if pd.notna(row.get('ioc_hashes')) and row['ioc_hashes'] != "Unknown":
            iocs.append(f"Hashes: {row['ioc_hashes']}")
        if pd.notna(row.get('ioc_ips')) and row['ioc_ips'] != "0.0.0.0":
            iocs.append(f"IPs: {row['ioc_ips']}")
        if pd.notna(row.get('ioc_domains')) and row['ioc_domains'] != "unknown.com":
            iocs.append(f"Domains: {row['ioc_domains']}")
        if pd.notna(row.get('ioc_files')) and row['ioc_files'] != "unknown.exe":
            iocs.append(f"Files: {row['ioc_files']}")
        
        if iocs:
            text_parts.append("IOCs: " + ", ".join(iocs))
        
        return " | ".join(text_parts)
    
    def create_embeddings(self, df, is_chain_data=False, batch_size=256, save_dir=None):
        """
        Process the dataframe, create text representations, and generate embeddings.
        
        Args:
            df: Pandas DataFrame with security incident data
            is_chain_data: Whether the data is attack chain data
            batch_size: Batch size for processing embeddings (higher uses more VRAM)
            save_dir: Directory to save intermediate results
        """
        # Set appropriate instruction based on data type
        if is_chain_data:
            self.instruction = "Represent this attack chain for security similarity matching"
        else:
            self.instruction = "Represent this security event for threat detection"
            
        print(f"Creating text representations from {len(df)} records...")
        
        # Clear previous texts and metadata
        self.texts = []
        self.metadata = []
        
        # Create text representations for each row
        for _, row in tqdm(df.iterrows(), total=len(df), desc="Creating text representations"):
            if is_chain_data:
                text = self._create_text_for_chain_embedding(row)
                # Fields to include in metadata for chains
                metadata_fields = [
                    'chain_id', 'attack_name', 'severity', 'first_seen', 'last_seen',
                    'duration_hours', 'mitre_techniques', 'chain_stages'
                ]
            else:
                text = self._create_text_for_embedding(row)
                # Fields to include in metadata for incidents
                metadata_fields = [
                    'Id', 'IncidentId', 'AlertId', 'Timestamp', 'Category', 'IncidentGrade'
                ]
            
            if text.strip():  # Only include non-empty texts
                self.texts.append(text)
                # Store metadata for retrieval
                metadata = {}
                for field in metadata_fields:
                    if field in row and pd.notna(row[field]):
                        metadata[field] = row[field]
                self.metadata.append(metadata)
                
        # Save intermediate results if directory provided
        if save_dir:
            os.makedirs(save_dir, exist_ok=True)
            with open(os.path.join(save_dir, "texts.pkl"), "wb") as f:
                pickle.dump(self.texts, f)
            with open(os.path.join(save_dir, "metadata.pkl"), "wb") as f:
                pickle.dump(self.metadata, f)
        
        print(f"Generated {len(self.texts)} text representations")
        
        # Generate embeddings in batches to manage memory
        all_embeddings = np.zeros((len(self.texts), self.dimension), dtype=np.float32)
        
        # Use tqdm for better progress tracking
        for i in tqdm(range(0, len(self.texts), batch_size), desc="Generating embeddings"):
            batch_texts = self.texts[i:i+batch_size]
            print(f"Embedding batch {i//batch_size + 1}/{(len(self.texts)-1)//batch_size + 1}, size: {len(batch_texts)}")
            
            try:
                if self.model_type == "instructor":
                    # Format for INSTRUCTOR
                    instructor_inputs = [[self.instruction, text] for text in batch_texts]
                    batch_embeddings = self.embedding_model.encode(instructor_inputs, 
                                                                  convert_to_numpy=True, 
                                                                  show_progress_bar=False)
                else:
                    # Format for SentenceTransformer
                    batch_embeddings = self.embedding_model.encode(batch_texts, 
                                                                  convert_to_numpy=True, 
                                                                  show_progress_bar=False)
                
                # Store embeddings
                all_embeddings[i:i+len(batch_texts)] = batch_embeddings
                
                # Free memory
                if torch.cuda.is_available():
                    torch.cuda.empty_cache()
                gc.collect()
                
            except Exception as e:
                print(f"Error embedding batch {i//batch_size + 1}: {e}")
                # Fill with zeros as fallback
                all_embeddings[i:i+len(batch_texts)] = np.zeros((len(batch_texts), self.dimension), dtype=np.float32)
        
        # Normalize embeddings for cosine similarity
        faiss.normalize_L2(all_embeddings)
        
        # Create and populate the FAISS index
        self.index = faiss.IndexFlatIP(self.dimension)  # Inner product for cosine similarity with normalized vectors
        self.index.add(all_embeddings)
        
        print(f"Created FAISS index with {self.index.ntotal} vectors of dimension {self.dimension}")
        return all_embeddings
    
    def save(self, directory="faiss_store", is_chain_data=False):
        """Save the FAISS index and related data to disk"""
        if is_chain_data:
            directory = f"{directory}_chains"
            
        os.makedirs(directory, exist_ok=True)
        
        # Save the FAISS index
        faiss.write_index(self.index, os.path.join(directory, "incidents.index"))
        
        # Save the texts and metadata
        with open(os.path.join(directory, "texts.pkl"), "wb") as f:
            pickle.dump(self.texts, f)
        
        with open(os.path.join(directory, "metadata.pkl"), "wb") as f:
            pickle.dump(self.metadata, f)
        
        # Save model info
        with open(os.path.join(directory, "model_info.txt"), "w") as f:
            f.write(f"Model: {self.model_name}\n")
            f.write(f"Dimension: {self.dimension}\n")
            f.write(f"Instruction: {self.instruction}\n")
            f.write(f"Model Type: {self.model_type}\n")
            f.write(f"Is Chain Data: {is_chain_data}\n")
        
        print(f"Saved FAISS index and data to {directory}")
    
    @classmethod
    def load(cls, directory="faiss_store"):
        """Load a saved FAISS index and related data"""
        # Load model info
        with open(os.path.join(directory, "model_info.txt"), "r") as f:
            lines = f.readlines()
            model_name = lines[0].split(": ")[1].strip()
            dimension = int(lines[1].split(": ")[1].strip())
            instruction = lines[2].split(": ")[1].strip()
            model_type = lines[3].split(": ")[1].strip() if len(lines) > 3 else "sentence_transformer"
            is_chain_data = lines[4].split(": ")[1].strip().lower() == "true" if len(lines) > 4 else False
        
        # Create instance with instructor disabled if the saved model wasn't instructor
        use_instructor = model_type == "instructor"
        instance = cls(model_name=model_name, dimension=dimension, use_instructor=use_instructor)
        instance.instruction = instruction
        instance.model_type = model_type
        
        # Load the FAISS index
        instance.index = faiss.read_index(os.path.join(directory, "incidents.index"))
        
        # Load texts and metadata
        with open(os.path.join(directory, "texts.pkl"), "rb") as f:
            instance.texts = pickle.load(f)
        
        with open(os.path.join(directory, "metadata.pkl"), "rb") as f:
            instance.metadata = pickle.load(f)
        
        print(f"Loaded FAISS index with {instance.index.ntotal} vectors")
        return instance
    
    def query(self, query_text, k=5):
        """
        Query the FAISS index with a text query.
        
        Args:
            query_text: The text query to search for
            k: Number of results to return
            
        Returns:
            List of (text, metadata, score) tuples for the top k results
        """
        try:
            # Encode the query
            if self.model_type == "instructor":
                query_embedding = self.embedding_model.encode([[self.instruction, query_text]], convert_to_numpy=True)
            else:
                query_embedding = self.embedding_model.encode([query_text], convert_to_numpy=True)
            
            # Normalize the query embedding for cosine similarity
            faiss.normalize_L2(query_embedding)
            
            # Search the index
            scores, indices = self.index.search(query_embedding, k)
            
            # Collect results
            results = []
            for i, idx in enumerate(indices[0]):
                if idx != -1:  # Valid index
                    results.append({
                        'text': self.texts[idx],
                        'metadata': self.metadata[idx],
                        'score': float(scores[0][i])
                    })
            
            return results
        except Exception as e:
            print(f"Error querying index: {e}")
            return []
    
    def get_all_index_stats(self):
        """Get statistics about the FAISS index"""
        return {
            'num_vectors': self.index.ntotal,
            'dimension': self.dimension,
            'num_texts': len(self.texts),
            'num_metadata': len(self.metadata),
            'model_name': self.model_name,
            'model_type': self.model_type,
            'instruction': self.instruction
        }


def process_incident_data(file_path, vector_store, chunksize=2000, temp_dir=None, embedding_batch_size=256):
    """
    Process a large CSV file with security incidents in chunks and build the FAISS index.
    
    Args:
        file_path: Path to the CSV file
        vector_store: EnhancedFAISSVectorStore instance
        chunksize: Number of rows to process at a time
        temp_dir: Directory to save intermediate results
        embedding_batch_size: Batch size for embedding generation
    """
    if temp_dir:
        os.makedirs(temp_dir, exist_ok=True)
    
    total_processed = 0
    
    # Process the CSV in chunks
    for chunk_num, chunk in enumerate(pd.read_csv(file_path, chunksize=chunksize)):
        print(f"Processing chunk {chunk_num+1}, rows {total_processed} to {total_processed + len(chunk)}")
        
        # Create embeddings for this chunk
        vector_store.create_embeddings(chunk, is_chain_data=False, batch_size=embedding_batch_size, save_dir=temp_dir)
        
        total_processed += len(chunk)
        print(f"Total processed: {total_processed} rows")
        
        # Free memory
        if torch.cuda.is_available():
            torch.cuda.empty_cache()
        gc.collect()
    
    # Save the final index
    vector_store.save(is_chain_data=False)
    print(f"Finished processing {total_processed} rows of incident data")


def process_chain_data(file_path, vector_store, temp_dir=None, embedding_batch_size=256, chunksize=2000):
    """
    Process attack chain data and build a separate FAISS index.
    
    Args:
        file_path: Path to the CSV file
        vector_store: EnhancedFAISSVectorStore instance
        temp_dir: Directory to save intermediate results
        embedding_batch_size: Batch size for embedding generation
        chunksize: Number of rows to process if chunking is needed
    """
    if temp_dir:
        os.makedirs(temp_dir, exist_ok=True)
        
    print(f"Processing attack chain data from {file_path}")
    
    try:
        chains_df = pd.read_csv(file_path)
        print(f"Loaded {len(chains_df)} attack chains")
        
        # Create embeddings for the chain data
        vector_store.create_embeddings(chains_df, is_chain_data=True, batch_size=embedding_batch_size, save_dir=temp_dir)
        
        # Save the final index
        vector_store.save(is_chain_data=True)
        print(f"Finished processing {len(chains_df)} attack chains")
    
    except Exception as e:
        print(f"Error processing chain data as a single file: {e}")
        print("Falling back to processing in chunks...")
        # If the file is too large, process it in chunks
        process_incident_data(file_path, vector_store, chunksize=chunksize, temp_dir=temp_dir, embedding_batch_size=embedding_batch_size)
        # Save with chain flag
        vector_store.save(is_chain_data=True)


def main():
    # Parse command line arguments
    parser = argparse.ArgumentParser(description="Create FAISS vector stores for security incidents and attack chains")
    
    # Input files
    parser.add_argument("--incidents_file", default="GUIDE_Train.csv", help="Path to incidents CSV file")
    parser.add_argument("--chains_file", default="chain_of_attacks_formatted.csv", help="Path to attack chains CSV file")
    
    # Output directories
    parser.add_argument("--incidents_output", default="faiss_store", help="Directory to save incidents vector store")
    parser.add_argument("--chains_output", default="faiss_store", help="Base directory for chains vector store")
    
    # Temp directories
    parser.add_argument("--temp_incidents", default="temp_incidents", help="Temp directory for incidents processing")
    parser.add_argument("--temp_chains", default="temp_chains", help="Temp directory for chains processing")
    
    # Processing parameters
    parser.add_argument("--embedding_batch_size", type=int, default=256, 
                       help="Batch size for embedding generation (higher uses more VRAM)")
    parser.add_argument("--chunk_size", type=int, default=2000, 
                      help="Chunk size for CSV processing (higher uses more RAM)")
    parser.add_argument("--use_instructor", action="store_true", help="Try to use INSTRUCTOR model first")
    
    args = parser.parse_args()
    
    # Create temp directories
    temp_incidents_dir = args.temp_incidents
    temp_chains_dir = args.temp_chains
    
    # Step 1: Process incidents data
    print(f"\n=== Processing Security Incidents Data (Batch Size: {args.embedding_batch_size}, Chunk Size: {args.chunk_size}) ===")
    
    if args.use_instructor:
        try:
            incidents_vector_store = EnhancedFAISSVectorStore(
                model_name="hkunlp/instructor-xl", 
                dimension=768,
                use_instructor=True
            )
            process_incident_data(args.incidents_file, incidents_vector_store, 
                                chunksize=args.chunk_size, temp_dir=temp_incidents_dir,
                                embedding_batch_size=args.embedding_batch_size)
        except Exception as e:
            print(f"Error with INSTRUCTOR model: {e}")
            print("Falling back to SentenceTransformer model")
            incidents_vector_store = EnhancedFAISSVectorStore(
                model_name="all-mpnet-base-v2", 
                dimension=768,
                use_instructor=False
            )
            process_incident_data(args.incidents_file, incidents_vector_store, 
                                chunksize=args.chunk_size, temp_dir=temp_incidents_dir,
                                embedding_batch_size=args.embedding_batch_size)
    else:
        incidents_vector_store = EnhancedFAISSVectorStore(
            model_name="all-mpnet-base-v2", 
            dimension=768,
            use_instructor=False
        )
        process_incident_data(args.incidents_file, incidents_vector_store, 
                            chunksize=args.chunk_size, temp_dir=temp_incidents_dir,
                            embedding_batch_size=args.embedding_batch_size)
    
    # Step 2: Process chains data
    print(f"\n=== Processing Attack Chains Data (Batch Size: {args.embedding_batch_size}) ===")
    
    if args.use_instructor:
        try:
            chains_vector_store = EnhancedFAISSVectorStore(
                model_name="hkunlp/instructor-xl", 
                dimension=768,
                use_instructor=True
            )
            process_chain_data(args.chains_file, chains_vector_store, temp_dir=temp_chains_dir,
                             embedding_batch_size=args.embedding_batch_size, chunksize=args.chunk_size)
        except Exception as e:
            print(f"Error with INSTRUCTOR model: {e}")
            print("Falling back to SentenceTransformer model")
            chains_vector_store = EnhancedFAISSVectorStore(
                model_name="all-mpnet-base-v2", 
                dimension=768,
                use_instructor=False
            )
            process_chain_data(args.chains_file, chains_vector_store, temp_dir=temp_chains_dir,
                             embedding_batch_size=args.embedding_batch_size, chunksize=args.chunk_size)
    else:
        chains_vector_store = EnhancedFAISSVectorStore(
            model_name="all-mpnet-base-v2", 
            dimension=768,
            use_instructor=False
        )
        process_chain_data(args.chains_file, chains_vector_store, temp_dir=temp_chains_dir,
                         embedding_batch_size=args.embedding_batch_size, chunksize=args.chunk_size)
    
    # Step 3: Demonstrate queries
    print("\n=== Testing Incident Queries ===")
    incident_query = "What are the high severity incidents related to credential access?"
    incident_results = incidents_vector_store.query(incident_query, k=3)
    
    print(f"Query: '{incident_query}'")
    for i, result in enumerate(incident_results):
        print(f"\nResult {i+1} (Score: {result['score']:.4f}):")
        print(f"Text: {result['text']}")
        print(f"Metadata: {result['metadata']}")
    
    print("\n=== Testing Chain Queries ===")
    chain_query = "Find attack chains involving credential access and lateral movement"
    chain_results = chains_vector_store.query(chain_query, k=3)
    
    print(f"Query: '{chain_query}'")
    for i, result in enumerate(chain_results):
        print(f"\nResult {i+1} (Score: {result['score']:.4f}):")
        print(f"Text: {result['text']}")
        print(f"Metadata: {result['metadata']}")


if __name__ == "__main__":
    # Print GPU information
    if torch.cuda.is_available():
        print(f"GPU available: {torch.cuda.get_device_name(0)}")
        print(f"GPU memory: {torch.cuda.get_device_properties(0).total_memory / 1024**3:.2f} GB")
    else:
        print("No GPU available, using CPU for embeddings")
    
    main()
