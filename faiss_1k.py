import pandas as pd
import numpy as np
import faiss
import os
from sentence_transformers import SentenceTransformer
import torch
import pickle

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
    
    def create_embeddings(self, df, batch_size=128):
        """
        Process the dataframe, create text representations, and generate embeddings.
        
        Args:
            df: Pandas DataFrame with security incident data
            batch_size: Batch size for processing embeddings
        """
        print(f"Creating text representations from {len(df)} records...")
        
        # Create text representations for each row
        texts = []
        metadata_list = []
        
        for _, row in df.iterrows():
            text = self._create_text_for_embedding(row)
            if text.strip():  # Only include non-empty texts
                texts.append(text)
                # Store metadata for retrieval
                metadata_list.append({
                    'Id': row.get('Id'),
                    'IncidentId': row.get('IncidentId'),
                    'AlertId': row.get('AlertId'),
                    'Timestamp': row.get('Timestamp'),
                    'Category': row.get('Category'),
                    'IncidentGrade': row.get('IncidentGrade')
                })
        
        print(f"Generated {len(texts)} text representations")
        
        # Generate embeddings in batches to manage memory
        embeddings = []
        for i in range(0, len(texts), batch_size):
            batch_texts = texts[i:i+batch_size]
            print(f"Embedding batch {i//batch_size + 1}/{(len(texts)-1)//batch_size + 1}")
            batch_embeddings = self.embedding_model.encode(batch_texts, convert_to_numpy=True, show_progress_bar=True)
            embeddings.append(batch_embeddings)
        
        # Combine all batches
        all_embeddings = np.vstack(embeddings)
        
        # Normalize embeddings for cosine similarity
        faiss.normalize_L2(all_embeddings)
        
        # Create and populate the FAISS index
        self.index = faiss.IndexFlatIP(self.dimension)  # Inner product for cosine similarity with normalized vectors
        self.index.add(all_embeddings)
        
        self.texts = texts
        self.metadata = metadata_list
        
        print(f"Created FAISS index with {self.index.ntotal} vectors of dimension {self.dimension}")
        return all_embeddings
    
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
    
    def get_all_index_stats(self):
        """Get statistics about the FAISS index"""
        return {
            'num_vectors': self.index.ntotal,
            'dimension': self.dimension,
            'num_texts': len(self.texts),
            'num_metadata': len(self.metadata),
            'model_name': self.model_name
        }


def process_large_csv(file_path, vector_store, chunksize=10000):
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
        vector_store.create_embeddings(chunk)
        
        total_processed += len(chunk)
        print(f"Total processed: {total_processed} rows")
    
    # Save the final index
    vector_store.save()
    print(f"Finished processing {total_processed} rows")


def main():
    # Path to your CSV file
    csv_file = "GUIDE_Train.csv"  # For full dataset, use the 9M row file
    
    # Choose a model - for 3GB of data, using a smaller model dimension helps with memory
    # all-MiniLM-L6-v2 (384 dimensions) is a good balance of quality and size
    # For higher quality but more memory: all-mpnet-base-v2 (768 dimensions)
    model_name = "all-MiniLM-L6-v2"
    dimension = 384
    
    # Initialize the vector store
    vector_store = FAISSVectorStore(model_name=model_name, dimension=dimension)
    
    # Process the CSV file
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
    main()
