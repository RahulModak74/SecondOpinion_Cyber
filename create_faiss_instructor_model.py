import pandas as pd
import numpy as np
import faiss
import os
import torch
from InstructorEmbedding import INSTRUCTOR
import pickle
import gc
import time
from tqdm import tqdm

class EnhancedFAISSVectorStore:
    def __init__(self, model_name="hkunlp/instructor-xl", dimension=768):
        """
        Initialize the FAISS vector store with the INSTRUCTOR embedding model.
        
        Args:
            model_name: The INSTRUCTOR model to use for embeddings
            dimension: The dimension of the embedding vectors (768 for instructor-xl)
        """
        self.model_name = model_name
        self.dimension = dimension
        
        print(f"Loading INSTRUCTOR model: {model_name}")
        self.embedding_model = INSTRUCTOR(model_name)
        
        # Move model to GPU if available
        if torch.cuda.is_available():
            self.embedding_model.to(torch.device("cuda"))
            print("Using GPU for embeddings")
        else:
            print("GPU not available, using CPU for embeddings")
        
        # Initialize index with IVF for faster search (more suitable for large datasets)
        # We'll create this properly once we know the number of vectors
        self.index = None
        self.texts = []
        self.metadata = []
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
    
    def batch_process(self, df, is_chain_data=False, batch_size=16, save_interval=1000, save_dir="faiss_store_temp"):
        """
        Process the dataframe in batches, progressively building the index.
        Optimized for GPUs and INSTRUCTOR model.
        
        Args:
            df: Pandas DataFrame with security incident data
            is_chain_data: Whether the data is attack chain data
            batch_size: Batch size for processing embeddings (smaller for INSTRUCTOR)
            save_interval: Save index after processing this many records
            save_dir: Directory to save temporary indices
        """
        os.makedirs(save_dir, exist_ok=True)
        
        # Create text representations for each row and store metadata
        print("Creating text representations...")
        for i, (_, row) in enumerate(tqdm(df.iterrows(), total=len(df))):
            if is_chain_data:
                text = self._create_text_for_chain_embedding(row)
                metadata_fields = [
                    'chain_id', 'attack_name', 'severity', 'first_seen', 'last_seen',
                    'duration_hours', 'mitre_techniques', 'chain_stages'
                ]
            else:
                text = self._create_text_for_embedding(row)
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
            
            # Save progress at intervals
            if (i + 1) % save_interval == 0:
                print(f"Processed {i + 1} rows, saving progress...")
                with open(os.path.join(save_dir, "texts.pkl"), "wb") as f:
                    pickle.dump(self.texts, f)
                with open(os.path.join(save_dir, "metadata.pkl"), "wb") as f:
                    pickle.dump(self.metadata, f)
        
        # Save final texts and metadata
        with open(os.path.join(save_dir, "texts.pkl"), "wb") as f:
            pickle.dump(self.texts, f)
        with open(os.path.join(save_dir, "metadata.pkl"), "wb") as f:
            pickle.dump(self.metadata, f)
        
        print(f"Created {len(self.texts)} text representations")
        
        # Initialize appropriate FAISS index based on dataset size
        self._init_index(len(self.texts))
        
        # Process in smaller batches for embedding generation
        total_vectors = len(self.texts)
        batches = [self.texts[i:i+batch_size] for i in range(0, total_vectors, batch_size)]
        
        # Process batches
        for batch_idx, batch_texts in enumerate(tqdm(batches, desc="Embedding batches")):
            start_time = time.time()
            print(f"Embedding batch {batch_idx+1}/{len(batches)}")
            
            # Format for INSTRUCTOR - each text needs an instruction
            instructor_inputs = [
                [self.instruction, text] for text in batch_texts
            ]
            
            # Generate embeddings - INSTRUCTOR may need smaller batches
            batch_embeddings = self.embedding_model.encode(instructor_inputs, convert_to_numpy=True, show_progress_bar=False)
            
            # Normalize embeddings
            faiss.normalize_L2(batch_embeddings)
            
            # Add to index
            self.index.add(batch_embeddings)
            
            # Free GPU memory
            torch.cuda.empty_cache()
            gc.collect()
            
            # Save progress periodically
            if (batch_idx + 1) % 20 == 0:
                print(f"Saving index progress after {(batch_idx + 1) * batch_size} embeddings...")
                faiss.write_index(self.index, os.path.join(save_dir, "partial_index.index"))
            
            end_time = time.time()
            print(f"Batch processed in {end_time - start_time:.2f} seconds")
        
        print(f"Created FAISS index with {self.index.ntotal} vectors of dimension {self.dimension}")
    
    def _init_index(self, num_vectors):
        """Initialize the appropriate FAISS index based on dataset size"""
        print(f"Initializing FAISS index for {num_vectors} vectors of dimension {self.dimension}")
        
        # For small datasets, use flat index
        if num_vectors < 10000:
            print("Using FlatIP index for small dataset")
            self.index = faiss.IndexFlatIP(self.dimension)
        else:
            # For larger datasets, use IVF index which is faster
            # The nlist parameter controls the number of clusters
            # A good rule of thumb is sqrt(num_vectors)
            nlist = min(int(4 * np.sqrt(num_vectors)), num_vectors // 10)
            nlist = max(nlist, 100)  # At least 100 clusters
            
            print(f"Using IVF{nlist}Flat index for large dataset")
            
            # Create a training set for the clustering
            # We'll use a subset of the vectors we're going to add
            # For very large datasets, we might need to create this on-the-fly
            quantizer = faiss.IndexFlatIP(self.dimension)
            self.index = faiss.IndexIVFFlat(quantizer, self.dimension, nlist, faiss.METRIC_INNER_PRODUCT)
            
            # For GPU usage, we can use GPU index
            if torch.cuda.is_available():
                # Move to GPU for training
                res = faiss.StandardGpuResources()
                gpu_index = faiss.index_cpu_to_gpu(res, 0, self.index)
                
                # Use a smaller subset for training if memory is a concern
                train_size = min(num_vectors, 100000)
                print(f"Training IVF index with {train_size} vectors...")
                
                # We'll train this later once we have the vectors
                self.index_needs_training = True
                return
            
            self.index_needs_training = True
    
    def create_embeddings(self, df, is_chain_data=False, batch_size=16):
        """
        Process the dataframe, create text representations, and generate embeddings.
        
        Args:
            df: Pandas DataFrame with security incident or attack chain data
            is_chain_data: Whether the data is attack chain data
            batch_size: Batch size for processing embeddings
        """
        print(f"Creating embeddings from {len(df)} records...")
        
        # Set the appropriate embedding instruction
        if is_chain_data:
            self.instruction = "Represent this attack chain for security similarity matching"
        else:
            self.instruction = "Represent this security event for threat detection"
        
        # Call the batch process method
        self.batch_process(df, is_chain_data=is_chain_data, batch_size=batch_size)
        
        # Return the index
        return self.index
    
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
        
        # Save model info and instruction
        with open(os.path.join(directory, "model_info.txt"), "w") as f:
            f.write(f"Model: {self.model_name}\n")
            f.write(f"Dimension: {self.dimension}\n")
            f.write(f"Instruction: {self.instruction}\n")
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
            is_chain_data = lines[3].split(": ")[1].strip().lower() == "true"
        
        # Create instance
        instance = cls(model_name=model_name, dimension=dimension)
        instance.instruction = instruction
        
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
        # Encode the query with instruction
        query_embedding = self.embedding_model.encode([[self.instruction, query_text]], convert_to_numpy=True)
        
        # Normalize the query embedding
        faiss.normalize_L2(query_embedding)
        
        # Make sure index is trained
        if hasattr(self.index, 'is_trained') and not self.index.is_trained:
            print("WARNING: Index is not trained, searching may be inefficient")
        
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


def process_incident_data(file_path, vector_store, chunksize=1000):
    """
    Process a large CSV file with security incidents in chunks and build the FAISS index.
    
    Args:
        file_path: Path to the CSV file
        vector_store: EnhancedFAISSVectorStore instance
        chunksize: Number of rows to process at a time
    """
    total_processed = 0
    
    # Process the CSV in chunks
    for chunk_num, chunk in enumerate(pd.read_csv(file_path, chunksize=chunksize)):
        print(f"Processing chunk {chunk_num+1}, rows {total_processed} to {total_processed + len(chunk)}")
        
        # Create embeddings for this chunk
        vector_store.create_embeddings(chunk, is_chain_data=False, batch_size=16)  # Smaller batch size for INSTRUCTOR
        
        total_processed += len(chunk)
        print(f"Total processed: {total_processed} rows")
        
        # Force garbage collection to free memory
        gc.collect()
        torch.cuda.empty_cache()
    
    # Save the final index
    vector_store.save(is_chain_data=False)
    print(f"Finished processing {total_processed} rows")


def process_chain_data(file_path, vector_store):
    """
    Process attack chain data and build a separate FAISS index.
    
    Args:
        file_path: Path to the CSV file
        vector_store: EnhancedFAISSVectorStore instance
    """
    print(f"Processing attack chain data from {file_path}")
    
    # For chain data, we might want to process the entire file at once
    # since it's likely smaller than the incident data
    try:
        chains_df = pd.read_csv(file_path)
        print(f"Loaded {len(chains_df)} attack chains")
        
        # Create embeddings for the chain data
        vector_store.create_embeddings(chains_df, is_chain_data=True, batch_size=16)
        
        # Save the final index
        vector_store.save(is_chain_data=True)
        print(f"Finished processing {len(chains_df)} attack chains")
    
    except Exception as e:
        print(f"Error processing chain data: {e}")
        # If the file is too large, we could process it in chunks similarly to incident data


def main():
    # Paths to your data files
    incidents_file = "GUIDE_Train.csv"  # Individual incidents
    chains_file = "chain_of_attacks_formatted.csv"  # Attack chains
    
    # Choose INSTRUCTOR model
    model_name = "hkunlp/instructor-xl"  # 768 dimensions
    dimension = 768
    
    # Process individual incidents
    print("\n=== Processing Individual Security Incidents ===")
    incidents_vector_store = EnhancedFAISSVectorStore(model_name=model_name, dimension=dimension)
    process_incident_data(incidents_file, incidents_vector_store, chunksize=1000)
    
    # Process attack chains
    print("\n=== Processing Attack Chains ===")
    chains_vector_store = EnhancedFAISSVectorStore(model_name=model_name, dimension=dimension)
    process_chain_data(chains_file, chains_vector_store)
    
    # Demonstration queries
    print("\n=== Testing Incident Queries ===")
    incident_query = "What are the high severity incidents related to credential access?"
    incident_results = incidents_vector_store.query(incident_query, k=3)
    
    print(f"Query: '{incident_query}'")
    for i, result in enumerate(incident_results):
        print(f"\nResult {i+1} (Score: {result['score']:.4f}):")
        print(f"Text: {result['text']}")
        print(f"Metadata: {result['metadata']}")
    
    print("\n=== Testing Chain Queries ===")
    chain_query = "What attack chains involve credential access techniques?"
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
        print("No GPU available, running on CPU")
    
    main()
