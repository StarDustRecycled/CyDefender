from typing import List, Dict, Any
from langchain_chroma import Chroma
from langchain_huggingface import HuggingFaceEmbeddings
from langchain.text_splitter import MarkdownTextSplitter, RecursiveCharacterTextSplitter
from langchain_core.documents import Document
import os
from pathlib import Path
import json

class SecurityKnowledgeBase:
    def __init__(self, 
                 docs_directory: str = "./security_docs",
                 persist_directory: str = "./security_kb"):
        """Initialize the security knowledge base"""
        self.docs_directory = Path(docs_directory)
        self.persist_directory = Path(persist_directory)
        self.embeddings = HuggingFaceEmbeddings(
            model_name="sentence-transformers/all-MiniLM-L6-v2",
        )
        # Use different splitters for different content types
        self.markdown_splitter = MarkdownTextSplitter(
            chunk_size=800,
            chunk_overlap=100
        )
        self.code_splitter = RecursiveCharacterTextSplitter(
            chunk_size=600,
            chunk_overlap=80,
            separators=["\n\n", "\n", " ", ""]
        )
        
        # Initialize or load existing vector store
        if self.persist_directory.exists():
            self.vector_store = Chroma(
                persist_directory=str(self.persist_directory),
                embedding_function=self.embeddings
            )
        else:
            self.vector_store = None
    
    def load_markdown_file(self, file_path: Path) -> List[Document]:
        """Load and process a single markdown file with enhanced metadata"""
        # Read the markdown content
        content = file_path.read_text(encoding='utf-8')
        
        # Extract enhanced metadata from file path structure
        path_parts = file_path.parts
        category = file_path.parent.name
        
        # Determine document type based on path structure
        doc_type = "general"
        if "threat_intelligence" in str(file_path):
            doc_type = "threat_intel"
        elif "incident_response" in str(file_path):
            doc_type = "incident_response"
        elif "mitre_attack" in str(file_path):
            doc_type = "mitre_attack"
        elif "defensive_measures" in str(file_path):
            doc_type = "defensive"
        elif "forensics" in str(file_path):
            doc_type = "forensics"
        
        # Enhanced metadata extraction
        metadata = {
            "title": file_path.stem,
            "category": category,
            "doc_type": doc_type,
            "source_file": str(file_path),
            "file_size": len(content)
        }
        
        # Extract MITRE ATT&CK IDs if present
        mitre_ids = self._extract_mitre_ids(content)
        if mitre_ids:
            # Convert lists to strings for ChromaDB compatibility
            metadata["mitre_tactics"] = ",".join(mitre_ids.get("tactics", []))
            metadata["mitre_techniques"] = ",".join(mitre_ids.get("techniques", []))
        
        # Choose appropriate text splitter based on content
        if "```" in content or "SELECT" in content or "import " in content:
            # Contains code blocks, use code splitter
            texts = self.code_splitter.split_text(content)
        else:
            # Regular markdown content
            texts = self.markdown_splitter.split_text(content)
        
        # Create documents with enhanced metadata
        docs = []
        for i, text in enumerate(texts):
            doc_metadata = {
                "chunk_id": i,
                "chunk_type": "code" if "```" in text else "text",
                **metadata
            }
            docs.append(Document(page_content=text, metadata=doc_metadata))
        
        return docs
    
    def _extract_mitre_ids(self, content: str) -> Dict[str, List[str]]:
        """Extract MITRE ATT&CK IDs from content"""
        import re
        
        # Patterns for MITRE IDs
        tactic_pattern = r"TA\d{4}"
        technique_pattern = r"T\d{4}(?:\.\d{3})?"
        
        tactics = re.findall(tactic_pattern, content)
        techniques = re.findall(technique_pattern, content)
        
        return {
            "tactics": list(set(tactics)),
            "techniques": list(set(techniques))
        }
    
    def initialize_knowledge_base(self):
        """Initialize the vector store with all markdown files in docs directory"""
        if not self.docs_directory.exists():
            raise ValueError(f"Documents directory {self.docs_directory} does not exist")
        
        all_docs = []
        
        # Recursively find all .md files
        for md_file in self.docs_directory.rglob("*.md"):
            docs = self.load_markdown_file(md_file)
            all_docs.extend(docs)
            print(f"Processed {md_file.name}")
        
        if not all_docs:
            raise ValueError("No markdown files found in documents directory")
        
        # Create new vector store
        self.vector_store = Chroma.from_documents(
            documents=all_docs,
            embedding=self.embeddings,
            persist_directory=str(self.persist_directory)
        )
        # Note: ChromaDB automatically persists to disk in the new version
        
        print(f"Initialized knowledge base with {len(all_docs)} documents")
    
    def query_knowledge_base(self, query: str, n_results: int = 3, doc_type: str = None) -> List[Dict[str, Any]]:
        """Query the knowledge base for relevant security information with filtering"""
        if not self.vector_store:
            raise ValueError("Knowledge base not initialized")
        
        # Build filter for document type if specified
        filter_dict = {}
        if doc_type:
            filter_dict["doc_type"] = doc_type
        
        # Get relevant documents with optional filtering
        if filter_dict:
            docs = self.vector_store.similarity_search_with_relevance_scores(
                query, k=n_results, filter=filter_dict
            )
        else:
            docs = self.vector_store.similarity_search_with_relevance_scores(
                query, k=n_results
            )
        
        # Format results with enhanced information
        results = []
        for doc, score in docs:
            result = {
                "content": doc.page_content,
                "metadata": doc.metadata,
                "relevance_score": score,
                "doc_type": doc.metadata.get("doc_type", "unknown"),
                "mitre_techniques": doc.metadata.get("mitre_techniques", "").split(",") if doc.metadata.get("mitre_techniques") else []
            }
            results.append(result)
        
        return results
    
    def search_by_mitre_technique(self, technique_id: str, n_results: int = 5) -> List[Dict[str, Any]]:
        """Search for documents containing specific MITRE ATT&CK technique"""
        if not self.vector_store:
            raise ValueError("Knowledge base not initialized")
        
        # Search for documents with the specific MITRE technique
        docs = self.vector_store.similarity_search_with_relevance_scores(
            f"MITRE ATT&CK {technique_id}",
            k=n_results
        )
        
        # Filter results that actually contain the technique ID
        filtered_results = []
        for doc, score in docs:
            techniques_str = doc.metadata.get("mitre_techniques", "")
            techniques = techniques_str.split(",") if techniques_str else []
            if technique_id in techniques or technique_id in doc.page_content:
                filtered_results.append({
                    "content": doc.page_content,
                    "metadata": doc.metadata,
                    "relevance_score": score,
                    "technique_id": technique_id
                })
        
        return filtered_results
    
    def get_incident_response_procedures(self, incident_type: str) -> List[Dict[str, Any]]:
        """Get incident response procedures for specific incident types"""
        return self.query_knowledge_base(
            f"incident response {incident_type} procedures playbook",
            n_results=5,
            doc_type="incident_response"
        )
    
    def get_threat_intelligence(self, threat_type: str) -> List[Dict[str, Any]]:
        """Get threat intelligence for specific threat types"""
        return self.query_knowledge_base(
            f"{threat_type} attack indicators IOCs",
            n_results=5,
            doc_type="threat_intel"
        )

def setup_knowledge_base():
    """Set up and test the enhanced security knowledge base"""
    # Enhanced test queries for threat response
    test_queries = [
        "malware incident response procedures",
        "SQL injection attack indicators",
        "PowerShell execution detection",
        "data breach notification requirements",
        "MITRE ATT&CK T1059 command line execution"
    ]
    
    try:
        # Initialize knowledge base
        print("Initializing enhanced security knowledge base...")
        kb = SecurityKnowledgeBase()
        kb.initialize_knowledge_base()
        
        # Test general queries
        print("\nTesting enhanced knowledge base queries:")
        for query in test_queries:
            print(f"\nQuery: {query}")
            results = kb.query_knowledge_base(query, n_results=2)
            for i, result in enumerate(results):
                print(f"\nResult {i+1}:")
                print(f"  Relevance Score: {result['relevance_score']:.2f}")
                print(f"  Document Type: {result['doc_type']}")
                print(f"  Category: {result['metadata']['category']}")
                print(f"  MITRE Techniques: {result['mitre_techniques']}")
                print(f"  Source: {result['metadata']['source_file']}")
                print(f"  Content Preview: {result['content'][:150]}...")
        
        # Test specialized search functions
        print("\n" + "="*50)
        print("Testing specialized search functions:")
        
        # Test MITRE technique search
        print("\nSearching for MITRE T1059 (Command Line Execution):")
        mitre_results = kb.search_by_mitre_technique("T1059", n_results=2)
        for result in mitre_results:
            print(f"  Found in: {result['metadata']['title']}")
            print(f"  Relevance: {result['relevance_score']:.2f}")
        
        # Test incident response search
        print("\nSearching for malware incident response:")
        ir_results = kb.get_incident_response_procedures("malware")
        for result in ir_results[:2]:
            print(f"  Found: {result['metadata']['title']}")
            print(f"  Type: {result['doc_type']}")
        
        # Test threat intelligence search
        print("\nSearching for web application threat intelligence:")
        ti_results = kb.get_threat_intelligence("web application")
        for result in ti_results[:2]:
            print(f"  Found: {result['metadata']['title']}")
            print(f"  Type: {result['doc_type']}")
        
        print("\n" + "="*50)
        print("Knowledge base setup completed successfully!")
        return kb
        
    except Exception as e:
        print(f"Error setting up knowledge base: {str(e)}")
        import traceback
        traceback.print_exc()
        return None

if __name__ == "__main__":
    kb = setup_knowledge_base()