from utils.mylogger import MyLogger
import os
from models.llm import LLM
os.environ["PYTORCH_CUDA_ALLOC_CONF"] = "max_split_size_mb:256"

_model_name_map = {
    "deepseekcoder-33b": 'deepseek-ai/deepseek-coder-33b-instruct',
    "deepseekcoder-7b": 'deepseek-ai/deepseek-coder-7b-instruct-v1.5',
    "deepseekcoder-v2-15b": "deepseek-ai/DeepSeek-Coder-V2-Lite-Instruct",
    "deepseek-r1-7b": "deepseek-ai/DeepSeek-R1-Distill-Llama-8B"
}

class DeepSeekModel(LLM):
    def __init__(self, model_name, logger: MyLogger, **kwargs):
        # Ensure HF cache dir is used if set
        if os.environ.get("HF_HOME"):
            os.environ.setdefault("HF_DATASETS_CACHE", os.environ["HF_HOME"])  # harmless if unused
        super().__init__(model_name, logger, _model_name_map, **kwargs)
        # Initialize terminators after pipeline is ready (only for non-GPT models)
        if hasattr(self, 'pipe') and self.pipe is not None:
            self.terminators = [
                self.pipe.tokenizer.eos_token_id,
                #self.pipe.tokenizer.convert_tokens_to_ids("<|eot_id|>")
            ]
        else:
            self.terminators = []

    def predict(self, main_prompt, batch_size=0, no_progress_bar=False):
        def rename(d):
            newd = dict()
            newd["role"]="user"
            newd["content"]=d[0]['content'] + '\n'+ d[1]['content']
            #print(d)
            #print(newd)
            return [newd]
            
        if batch_size > 0:
            prompts = [self.pipe.tokenizer.apply_chat_template(rename(p), tokenize=False, add_generation_prompt=True) for p in main_prompt]
            #print(prompts[0])
            return self.predict_main(prompts, batch_size=batch_size, no_progress_bar=no_progress_bar)
        else:
           
            prompt = self.pipe.tokenizer.apply_chat_template(
            main_prompt, 
            tokenize=False, 
            add_generation_prompt=True
            )
            l = len(self.tokenizer.tokenize(prompt))
            self.log("Prompt length:" + str(l))
            limit = self.model_hyperparams.get("max_input_tokens", 16000)
            if l > limit:
                return "Too long, skipping: "+str(l)
            #print(prompt)
            return self.predict_main(prompt, no_progress_bar=no_progress_bar)
        
