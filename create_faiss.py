import pandas as pd
import numpy as np
import faiss
import os
import torch
from sentence_transformers import SentenceTransformer
import pickle
import gc
import time

class FAISSVectorStore:
    def __init__(self, model_name="all-MiniLM-L6-v2", dimension=384):
        """
        Initialize the FAISS vector store with a specific embedding model.
        
        Args:
            model_name: The SentenceTransformer model to use for embeddings
            dimension: The dimension of the embedding vectors
        """
        self.model_name = model_name
        self.dimension = dimension
        self.embedding_model = SentenceTransformer(model_name)
        
        # Move model to GPU if available
        if torch.cuda.is_available():
            self.embedding_model = self.embedding_model.to(torch.device("cuda"))
            print("Using GPU for embeddings")
        else:
            print("GPU not available, using CPU for embeddings")
        
        self.index = None
        self.texts = []
        self.metadata = []
        
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
    
    def batch_process(self, df, batch_size=64, save_interval=10000, save_dir="faiss_store_temp"):
        """
        Process the dataframe in batches, progressively building the index.
        Optimized for GPUs with limited memory.
        
        Args:
            df: Pandas DataFrame with security incident data
            batch_size: Batch size for processing embeddings
            save_interval: Save index after processing this many records
            save_dir: Directory to save temporary indices
        """
        os.makedirs(save_dir, exist_ok=True)
        
        # Create CPU index for storage
        cpu_index = faiss.IndexFlatIP(self.dimension)
        
        # Create text representations for each row and store metadata
        for i, (_, row) in enumerate(df.iterrows()):
            text = self._create_text_for_embedding(row)
            if text.strip():  # Only include non-empty texts
                self.texts.append(text)
                # Store metadata for retrieval
                self.metadata.append({
                    'Id': row.get('Id'),
                    'IncidentId': row.get('IncidentId'),
                    'AlertId': row.get('AlertId'),
                    'Timestamp': row.get('Timestamp'),
                    'Category': row.get('Category'),
                    'IncidentGrade': row.get('IncidentGrade')
                })
            
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
        
        # Process in smaller batches for embedding generation
        total_vectors = len(self.texts)
        batches = [self.texts[i:i+batch_size] for i in range(0, total_vectors, batch_size)]
        
        # Create GPU resources
        res = faiss.StandardGpuResources()
        
        # Process batches
        for batch_idx, batch_texts in enumerate(batches):
            start_time = time.time()
            print(f"Embedding batch {batch_idx+1}/{len(batches)}")
            
            # Generate embeddings
            batch_embeddings = self.embedding_model.encode(batch_texts, convert_to_numpy=True, show_progress_bar=True)
            
            # Normalize embeddings for cosine similarity
            faiss.normalize_L2(batch_embeddings)
            
            # Add to CPU index
            cpu_index.add(batch_embeddings)
            
            # Free GPU memory
            torch.cuda.empty_cache()
            gc.collect()
            
            # Save progress periodically
            if (batch_idx + 1) % 20 == 0:
                print(f"Saving index progress after {(batch_idx + 1) * batch_size} embeddings...")
                faiss.write_index(cpu_index, os.path.join(save_dir, "partial_index.index"))
            
            end_time = time.time()
            print(f"Batch processed in {end_time - start_time:.2f} seconds")
        
        # Store the completed index
        self.index = cpu_index
        print(f"Created FAISS index with {self.index.ntotal} vectors of dimension {self.dimension}")
    
    def create_embeddings(self, df, batch_size=64):
        """
        Process the dataframe, create text representations, and generate embeddings.
        Main embedding creation method, using the batch process method.
        
        Args:
            df: Pandas DataFrame with security incident data
            batch_size: Batch size for processing embeddings
        """
        print(f"Creating embeddings from {len(df)} records...")
        
        # Call the batch process method
        self.batch_process(df, batch_size=batch_size)
        
        # Return the index
        return self.index
    
    def save(self, directory="faiss_store"):
        """Save the FAISS index and related data to disk"""
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
            f.write(f"Model: {self.model_name}\nDimension: {self.dimension}")
        
        print(f"Saved FAISS index and data to {directory}")
    
    @classmethod
    def load(cls, directory="faiss_store"):
        """Load a saved FAISS index and related data"""
        # Load model info
        with open(os.path.join(directory, "model_info.txt"), "r") as f:
            lines = f.readlines()
            model_name = lines[0].split(": ")[1].strip()
            dimension = int(lines[1].split(": ")[1].strip())
        
        # Create instance
        instance = cls(model_name=model_name, dimension=dimension)
        
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
        # Encode the query
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


def process_large_csv(file_path, vector_store, chunksize=1000):
    """
    Process a large CSV file in chunks and build the FAISS index.
    
    Args:
        file_path: Path to the CSV file
        vector_store: FAISSVectorStore instance
        chunksize: Number of rows to process at a time
    """
    total_processed = 0
    
    # Process the CSV in chunks
    for chunk_num, chunk in enumerate(pd.read_csv(file_path, chunksize=chunksize)):
        print(f"Processing chunk {chunk_num+1}, rows {total_processed} to {total_processed + len(chunk)}")
        
        # Create embeddings for this chunk
        vector_store.create_embeddings(chunk, batch_size=64)  # Adjusted for 6GB GPU
        
        total_processed += len(chunk)
        print(f"Total processed: {total_processed} rows")
        
        # Force garbage collection to free memory
        gc.collect()
        torch.cuda.empty_cache()
    
    # Save the final index
    vector_store.save()
    print(f"Finished processing {total_processed} rows")


def query_rag_system(query_text, k=5, vector_store_dir="faiss_store"):
    """
    Query the FAISS index and return relevant results.
    
    Args:
        query_text: The query text
        k: Number of results to return
        vector_store_dir: Directory containing the FAISS index
        
    Returns:
        List of results
    """
    # Load the vector store
    vector_store = FAISSVectorStore.load(vector_store_dir)
    
    # Query the vector store
    results = vector_store.query(query_text, k=k)
    
    return results


def main():
    # Path to your CSV file
    csv_file = "GUIDE_Train.csv"  # For full dataset, use the 9M row file
    
    # Choose a model - smaller dimension for 6GB GPU
    model_name = "all-MiniLM-L6-v2"  # 384 dimensions
    dimension = 384
    
    # Initialize the vector store
    vector_store = FAISSVectorStore(model_name=model_name, dimension=dimension)
    
    # Process the CSV file - use smaller batch size for 6GB GPU
    process_large_csv(csv_file, vector_store, chunksize=1000)
    
    # Demonstration query
    query = "What are the high severity incidents related to phishing?"
    results = vector_store.query(query, k=5)
    
    print("\nQuery Results:")
    print(f"Query: '{query}'")
    for i, result in enumerate(results):
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
