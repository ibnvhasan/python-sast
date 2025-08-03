"""
Base LLM class for model implementations
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import logging

class LLM(ABC):
    """Abstract base class for all LLM implementations."""
    
    def __init__(self, model_name: str, logger=None, model_name_map: Optional[Dict[str, str]] = None, **kwargs):
        """
        Initialize the LLM base class.
        
        Args:
            model_name: Name of the model
            logger: Logger instance
            model_name_map: Mapping of model names to actual model identifiers
            **kwargs: Additional model parameters
        """
        self.model_name = model_name
        self.logger = logger or logging.getLogger(__name__)
        self.model_name_map = model_name_map or {}
        self.kwargs = kwargs
        
        # Map model name if mapping exists
        self.actual_model_name = self.model_name_map.get(model_name, model_name)
        
        # Initialize transformers pipeline for HuggingFace models (not GPT)
        if not model_name.lower().startswith("gpt"):
            self._initialize_hf_pipeline()
    
    def _initialize_hf_pipeline(self):
        """Initialize HuggingFace transformers pipeline."""
        try:
            import transformers
            import torch
            from transformers import AutoTokenizer, AutoModelForCausalLM
            
            # Get the actual model ID
            if self.model_name not in self.model_name_map:
                self.log_error(f"Model {self.model_name} not found in model name map")
                self.log_error(f"Available models: {list(self.model_name_map.keys())}")
                raise ValueError(f"Unsupported model: {self.model_name}")
            
            model_id = self.model_name_map[self.model_name]
            self.log_info(f"Loading HuggingFace model: {model_id}")
            
            # Initialize tokenizer and model
            self.tokenizer = AutoTokenizer.from_pretrained(model_id, trust_remote_code=True)
            self.model = AutoModelForCausalLM.from_pretrained(
                model_id,
                torch_dtype=torch.float16,
                device_map="auto",
                trust_remote_code=True
            )
            
            # Create pipeline
            self.pipe = transformers.pipeline(
                "text-generation",
                model=self.model,
                tokenizer=self.tokenizer
            )
            
            # Configure tokenizer
            if self.pipe.tokenizer.pad_token_id is None:
                self.pipe.tokenizer.pad_token_id = self.pipe.tokenizer.eos_token_id
            self.pipe.tokenizer.padding_side = 'left'
            
            # Set default hyperparameters
            self.model_hyperparams = {
                'temperature': 0.01,
                'top_p': 0.9,
                'max_new_tokens': 1024,
                'max_input_tokens': 16000
            }
            
            self.log_info(f"Successfully initialized HuggingFace pipeline for {model_id}")
            
        except ImportError as e:
            self.log_error(f"Failed to import required libraries: {e}")
            self.log_error("Please install transformers and torch: pip install transformers torch")
            raise
        except Exception as e:
            self.log_error(f"Failed to initialize HuggingFace pipeline: {e}")
            raise
    
    def predict_main(self, prompt, batch_size=0, no_progress_bar=False):
        """Main prediction method for HuggingFace models."""
        try:
            if isinstance(prompt, list):
                # Batch processing
                results = []
                for p in prompt:
                    output = self.pipe(
                        p,
                        max_new_tokens=self.model_hyperparams.get('max_new_tokens', 1024),
                        temperature=self.model_hyperparams.get('temperature', 0.01),
                        top_p=self.model_hyperparams.get('top_p', 0.9),
                        pad_token_id=self.tokenizer.eos_token_id,
                        return_full_text=False,
                        do_sample=True
                    )
                    results.append(output[0]['generated_text'])
                return results
            else:
                # Single prompt
                output = self.pipe(
                    prompt,
                    max_new_tokens=self.model_hyperparams.get('max_new_tokens', 1024),
                    temperature=self.model_hyperparams.get('temperature', 0.01),
                    top_p=self.model_hyperparams.get('top_p', 0.9),
                    pad_token_id=self.tokenizer.eos_token_id,
                    return_full_text=False,
                    do_sample=True
                )
                return output[0]['generated_text']
        except Exception as e:
            self.log_error(f"Prediction failed: {e}")
            raise
    
    def log(self, message: str):
        """Log method for backward compatibility."""
        self.log_info(message)
        
    @abstractmethod
    def predict(self, prompt: List[Dict[str, str]], **kwargs) -> str:
        """
        Generate prediction from the model.
        
        Args:
            prompt: List of message dictionaries with 'role' and 'content' keys
            **kwargs: Additional parameters for prediction
            
        Returns:
            Generated text response
        """
        pass
    
    def preprocess_prompt(self, prompt: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Preprocess the prompt before sending to the model.
        Default implementation returns the prompt as-is.
        
        Args:
            prompt: Original prompt
            
        Returns:
            Preprocessed prompt
        """
        return prompt
    
    def postprocess_response(self, response: str) -> str:
        """
        Postprocess the response from the model.
        Default implementation returns the response as-is.
        
        Args:
            response: Raw model response
            
        Returns:
            Processed response
        """
        return response
    
    def log_info(self, message: str, phase: str = ""):
        """Log an info message."""
        if hasattr(self.logger, 'info'):
            if hasattr(self.logger, 'log') and phase:
                self.logger.log(message, "info", phase)
            else:
                self.logger.info(message)
        else:
            print(f"[INFO] {message}")
    
    def log_error(self, message: str, phase: str = ""):
        """Log an error message."""
        if hasattr(self.logger, 'error'):
            if hasattr(self.logger, 'log') and phase:
                self.logger.log(message, "error", phase)
            else:
                self.logger.error(message)
        else:
            print(f"[ERROR] {message}")
