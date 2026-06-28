# ai_brain.py - AI engine (LLM inference + default ONNX fallback)
import os
from pathlib import Path

_llm = None
_model_type = None  # "gguf" or "onnx"

def load_model(model_path: str):
    global _llm, _model_type
    ext = Path(model_path).suffix.lower()
    if ext == ".gguf":
        from llama_cpp import Llama
        _llm = Llama(model_path=model_path, n_ctx=4096, verbose=False)
        _model_type = "gguf"
    elif ext == ".onnx":
        import onnxruntime as ort
        # For a default dummy model we don't need a tokenizer
        session = ort.InferenceSession(model_path)
        _llm = session
        _model_type = "onnx"
    else:
        raise ValueError(f"Unsupported model format: {ext}")

def analyze(report: str) -> str:
    if _llm is None:
        raise RuntimeError("Model not loaded")

    if _model_type == "gguf":
        if len(report) > 3000:
            report = report[:3000] + "\n... (truncated)"
        prompt = f"""You are a malware analyst. Given the following analysis report, determine the most likely intent of the program. Choose from: ransomware, backdoor, trojan, keylogger, adware, coin miner, legitimate tool, system utility, script, etc. Explain concisely.

Report:
{report}

Intent and reasoning:"""
        output = _llm(prompt, max_tokens=256, stop=["\n\n"], echo=False)
        return output["choices"][0]["text"].strip()

    elif _model_type == "onnx":
        # Our default ONNX model outputs a single string constant.
        # It doesn't use the report, just returns a fixed message.
        inputs = _llm.get_inputs()
        if inputs[0].name == "dummy":
            output = _llm.run(None, {})[0]
            # output is a list of strings (batch size 1)
            return output[0].decode() if isinstance(output[0], bytes) else output[0]
        else:
            # Real ONNX model would need tokenization & generation loop
            return "[ONNX model requires full generation pipeline – please use a GGUF model for detailed analysis.]"

    return "Unknown model type"

def convert_gguf_to_onnx(input_gguf: str, output_onnx: str) -> str:
    """Try to convert using gguf2onnx (install with `pip install gguf2onnx`)."""
    try:
        import subprocess
        r = subprocess.run(
            ["python", "-m", "gguf2onnx", input_gguf, output_onnx],
            capture_output=True, text=True, timeout=300
        )
        if r.returncode == 0:
            return f"Conversion successful: {output_onnx}"
        else:
            return f"Conversion failed:\n{r.stderr}"
    except FileNotFoundError:
        return ("gguf2onnx not installed. Please run:\n"
                "  pip install gguf2onnx\n"
                "or manually convert using scripts from llama.cpp.")
    except Exception as e:
        return f"Conversion error: {e}"

def generate_default_onnx(output_onnx: str) -> str:
    """
    Create a small dummy ONNX model that always returns a fixed string.
    This allows the tool to work without any user-provided model.
    """
    try:
        import onnx
        from onnx import helper, TensorProto
        # Constant node that outputs a string
        text = "Default model – no real AI loaded.\nAnalysis: unable to determine intent. Please provide a proper .gguf or .onnx model."
        # ONNX doesn't directly store strings in graphs easily; we'll use a constant with a string tensor.
        # Simpler: use a node that outputs a fixed int array, then cast? Not needed.
        # We'll make a tiny graph with a single Constant node -> output.
        const_node = helper.make_node(
            'Constant',
            inputs=[],
            outputs=['text_output'],
            value=helper.make_tensor(
                name='value',
                data_type=TensorProto.STRING,
                dims=[1],
                vals=[text.encode('utf-8')]
            )
        )
        graph = helper.make_graph(
            nodes=[const_node],
            name='default_model',
            inputs=[],
            outputs=[helper.make_tensor_value_info('text_output', TensorProto.STRING, [1])]
        )
        model = helper.make_model(graph, producer_name='exe_intent')
        model.opset_import[0].version = 13
        onnx.checker.check_model(model)
        onnx.save(model, output_onnx)
        return f"Default model created at: {output_onnx}"
    except Exception as e:
        return f"Failed to generate default ONNX model: {e}"
