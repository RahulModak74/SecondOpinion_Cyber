# SecondOpinion Security Analyzer

A sophisticated security log analysis system that uses **Retrieval-Augmented Generation (RAG)** to provide intelligent threat assessment by matching new security events against historical incident data and attack chain patterns.

## 🎯 Overview

SecondOpinion combines vector similarity search with large language models to give security analysts a "second opinion" on security logs. It maintains two specialized knowledge bases:

1. **Individual Security Incidents** - Historical security events and alerts
2. **Attack Chain Patterns** - Multi-stage attack sequences and campaigns

When analyzing new logs, the system finds similar historical patterns and uses an LLM to provide contextualized threat analysis.

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Security Log  │───▶│  SecondOpinion   │───▶│   Analysis      │
│                 │    │    Analyzer      │    │   Report        │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │    Vector Stores     │
                    │ ┌─────────────────┐  │
                    │ │   Incidents     │  │
                    │ │   FAISS Index   │  │
                    │ └─────────────────┘  │
                    │ ┌─────────────────┐  │
                    │ │ Attack Chains   │  │
                    │ │   FAISS Index   │  │
                    │ └─────────────────┘  │
                    └──────────────────────┘
                               │
                               ▼
                    ┌──────────────────────┐
                    │     OpenRouter       │
                    │   (LLM Provider)     │
                    └──────────────────────┘
```

## 🚀 Features

- **Dual Vector Search**: Separate FAISS indices for incidents and attack chains
- **Flexible Embeddings**: Support for both INSTRUCTOR and SentenceTransformer models
- **Intelligent Analysis**: Uses Claude 3.5 Sonnet for security-focused analysis
- **Multiple Input Formats**: Supports CSV and plain text log files
- **GPU Acceleration**: Optimized for GPU-accelerated embedding generation
- **Batch Processing**: Efficient handling of large datasets
- **Structured Output**: Clean, actionable analysis reports

## 📦 Installation

### Prerequisites

- Python 3.8+
- CUDA-compatible GPU (recommended)
- OpenRouter API key

### Install Dependencies

```bash
pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu118
pip install faiss-gpu  # or faiss-cpu if no GPU
pip install sentence-transformers
pip install InstructorEmbedding
pip install pandas numpy requests tqdm
```

## 🔧 Setup

### 1. Prepare Your Data

**Incidents Data (`incidents.csv`)**:
Required columns: `AlertTitle`, `Category`, `MitreTechniques`, `IncidentGrade`, `ActionGrouped`, etc.

**Attack Chains Data (`chains.csv`)**:
Required columns: `chain_id`, `attack_name`, `mitre_techniques`, `severity`, `chain_stages`, etc.

### 2. Build Vector Indices

```bash
# Build incidents index
python build_vector_store.py --data incidents.csv --output faiss_store --type incidents

# Build attack chains index  
python build_vector_store.py --data chains.csv --output faiss_store_chains --type chains
```

### 3. Get OpenRouter API Key

Sign up at [OpenRouter](https://openrouter.ai) and get your API key.

## 🎮 Usage

### Basic Analysis

```bash
python second_opinion_improved.py \
  --log_file suspicious_activity.log \
  --incidents_store faiss_store \
  --chains_store faiss_store_chains \
  --openrouter_api_key your_api_key_here \
  --output analysis_result.json
```

### Advanced Usage

```bash
python second_opinion_improved.py \
  --log_file complex_attack.csv \
  --incidents_store faiss_store \
  --chains_store faiss_store_chains \
  --openrouter_api_key your_api_key_here \
  --incidents_k 10 \
  --chains_k 5 \
  --similarity_threshold 0.4 \
  --output detailed_analysis.json
```

### Parameters

- `--log_file`: Path to log file (CSV or text)
- `--incidents_store`: Path to incidents FAISS store
- `--chains_store`: Path to attack chains FAISS store  
- `--openrouter_api_key`: Your OpenRouter API key
- `--incidents_k`: Number of similar incidents to retrieve (default: 5)
- `--chains_k`: Number of similar chains to retrieve (default: 3)
- `--similarity_threshold`: Minimum similarity score (default: 0.35)
- `--output`: Output file path (optional)

## 📊 Output Format

The system provides structured analysis in 5 sections:

### 1. SUMMARY
Executive summary of the security event

### 2. ATTACK DETAILS  
- Specific suspicious techniques observed
- MITRE ATT&CK technique mappings
- Attacker objectives

### 3. THREAT ASSESSMENT
- Severity level (Low/Medium/High/Critical)
- Confidence percentage with reasoning
- Potential impact assessment

### 4. RECOMMENDATIONS
- Prioritized, actionable response steps
- Specific mitigation strategies

### 5. RELATED PATTERNS
- Analysis of historical pattern matches
- Context from similar incidents/chains

## 🗂️ File Structure

```
secondopinion/
├── second_opinion_improved.py     # Main analysis engine
├── build_vector_store.py          # Vector index builder
├── faiss_store/                   # Incidents vector store
│   ├── incidents.index
│   ├── texts.pkl
│   ├── metadata.pkl
│   └── model_info.txt
├── faiss_store_chains/            # Attack chains vector store
│   ├── incidents.index
│   ├── texts.pkl  
│   ├── metadata.pkl
│   └── model_info.txt
└── logs/                          # Sample log files
```

## ⚙️ Configuration

### Embedding Models

The system supports multiple embedding approaches:

```python
# INSTRUCTOR models (recommended)
model_name = "hkunlp/instructor-xl"      # 768 dimensions
model_name = "hkunlp/instructor-large"   # 768 dimensions

# SentenceTransformer models (fallback)  
model_name = "all-mpnet-base-v2"         # 768 dimensions
model_name = "all-MiniLM-L6-v2"          # 384 dimensions
```

### LLM Models

Available through OpenRouter:
- `anthropic/claude-3-5-sonnet` (recommended)
- `deepseek/deepseek-chat:latest` (cost-effective)
- `openai/gpt-4-turbo`

## 🔍 Example Analysis

**Input Log:**
```
2024-01-15 14:32:11 - Suspicious PowerShell execution detected
Process: powershell.exe -enc base64_encoded_command
Parent: winword.exe
User: john.doe@company.com
```

**Output:**
```json
{
  "summary": "Detected potential malicious macro execution via PowerShell...",
  "severity": "High", 
  "confidence": "85%",
  "mitre_techniques": ["T1059.001", "T1566.001"],
  "recommendations": [
    "Isolate affected host immediately",
    "Analyze PowerShell command content", 
    "Check for lateral movement indicators"
  ]
}
```

## 🚀 Performance Optimization

### GPU Memory Management
- Uses batch processing for large datasets
- Automatic GPU memory cleanup
- Configurable batch sizes based on VRAM

### FAISS Index Types
- **Small datasets (<10K)**: FlatIP index
- **Large datasets (>10K)**: IVF index with clustering

## 🛠️ Troubleshooting

### Common Issues

**CUDA out of memory:**
```bash
# Reduce batch size
python second_opinion_improved.py --batch_size 8
```

**Missing FAISS index:**
```bash
# Rebuild the index
python build_vector_store.py --data your_data.csv --output faiss_store
```

**OpenRouter API errors:**
- Check API key validity
- Verify model availability
- Monitor rate limits

## 📈 Future Enhancements

- [ ] Real-time log streaming analysis
- [ ] Custom MITRE ATT&CK framework integration
- [ ] Multi-language log support
- [ ] Advanced threat hunting queries
- [ ] Integration with SIEM platforms
- [ ] Federated learning across organizations

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- MITRE ATT&CK Framework
- Hugging Face Transformers
- Facebook FAISS
- OpenRouter API
- INSTRUCTOR Embedding Model
