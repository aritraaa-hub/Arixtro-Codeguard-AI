import gradio as gr
import re
import os
from huggingface_hub import InferenceClient

# ১. C কোড স্ট্যাটিক অ্যানালাইজার
def analyze_c_code(source_code):
    lines = source_code.split('\n')
    issues = []
    malloc_count = free_count = max_loop_depth = current_loop_depth = 0
    unsafe_functions = {
        r'\bgets\s*\(': "Critical Security Risk: 'gets()' causes buffer overflow.",
        r'\bstrcpy\s*\(': "Security Warning: 'strcpy()' does not check buffer bounds."
    }

    for line_num, line in enumerate(lines, start=1):
        clean_line = line.strip()
        for pattern, warning in unsafe_functions.items():
            if re.search(pattern, clean_line):
                issues.append(f"Line {line_num}: {warning}")
        if re.search(r'\b(malloc|calloc|realloc)\s*\(', clean_line): malloc_count += 1
        if re.search(r'\bfree\s*\(', clean_line): free_count += 1
        if re.search(r'\b(int|char|float|double|void)\s*\*\s*[a-zA-Z_][a-zA-Z0-9_]*\s*;', clean_line):
            issues.append(f"Line {line_num}: Uninitialized pointer declared.")
        if re.search(r'\b(for|while)\s*\(', clean_line):
            current_loop_depth += 1
            if current_loop_depth > max_loop_depth: max_loop_depth = current_loop_depth
            if current_loop_depth >= 2: issues.append(f"Line {line_num}: Nested loop detected.")
        if '}' in clean_line and current_loop_depth > 0: current_loop_depth -= 1

    if malloc_count > free_count: issues.append("Memory Leak Warning: Missing 'free()' call.")
    return {"language": "C", "detected_warnings": issues}

# ২. Hugging Face API ক্লায়েন্ট (Auto-Fallback System)
HF_TOKEN = os.environ.get("HF_TOKEN") 

def ai_auto_fix(source_code, static_report):
    if not static_report["detected_warnings"]:
        return "✅ No static issues found. The code seems structurally safe!"
        
    issues_list = "\n".join(static_report["detected_warnings"])
    prompt = (
        "You are Arixtro Codegaurd AI, an expert software security assistant.\n"
        f"Analyze this {static_report['language']} code:\n\n```c\n{source_code.strip()}\n```\n\n"
        f"Warnings:\n{issues_list}\n\n"
        "Tasks:\n1. Explain the danger.\n2. Provide the fixed memory-safe code.\n"
    )
    
    messages = [{"role": "system", "content": "You are Arixtro Codegaurd AI."}, {"role": "user", "content": prompt}]
    
    # ব্যাকআপ সিস্টেম: প্রথমটা ফেইল করলে দ্বিতীয়টা ট্রাই করবে
    models_to_try = [
        "mistralai/Mistral-7B-Instruct-v0.3",
        "HuggingFaceH4/zephyr-7b-beta"
    ]
    
    last_error = ""
    for model_name in models_to_try:
        try:
            client = InferenceClient(model=model_name, token=HF_TOKEN)
            response = client.chat_completion(messages, max_tokens=512, temperature=0.2)
            return f"*(Fixed by AI Engine)*\n\n" + response.choices[0].message.content
        except Exception as e:
            last_error = str(e)
            continue
            
    return f"⚠️ API Error: HF free models are currently not responding. Details: {last_error}"

def code_guard_ui(source_code):
    if not source_code.strip():
        return "⚠️ Please enter some code.", ""
    
    # স্ট্যাটিক অ্যানালাইজার দিয়ে কোড চেক করা
    static_report = analyze_c_code(source_code)
    
    if static_report["detected_warnings"]:
        warnings_str = "\n".join([f"* 🚨 **{w}**" for w in static_report["detected_warnings"]])
        report_text = f"### 🔍 Static Analysis Found {len(static_report['detected_warnings'])} Issues:\n\n{warnings_str}"
    else:
        report_text = "### ✅ No Static Issues Found."
    
    # এআই-কে দিয়ে ফিক্স করানো
    ai_response = ai_auto_fix(source_code, static_report)
    return report_text, ai_response

# ৩. Arixtro ব্র্যান্ডিং করা UI লেআউট (ইন্টারফেস)
sample_code = """#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n\nint main() {\n    char buffer[10];\n    int *ptr;\n    int *arr = (int*)malloc(5 * sizeof(int));\n    gets(buffer);\n    strcpy(buffer, "Hello");\n    for(int i = 0; i < 5; i++) {\n        for(int j = 0; j < 5; j++) {\n            arr[i] = i + j;\n        }\n    }\n    return 0;\n}"""

with gr.Blocks(theme=gr.themes.Monochrome(), title="Arixtro Codegaurd AI") as demo:
    gr.Markdown("<center><h1>🛡️ Arixtro Codegaurd AI</h1></center>")
    gr.Markdown("<center><b>Developed by Aritra Tarafder Riju | Advanced Code Vulnerability Detection Framework</b></center>")
    gr.Markdown("<center>Paste your C code below to detect memory leaks, buffer overflows, and get AI-optimized fixes in real-time.</center>")
    
    with gr.Row():
        with gr.Column():
            input_code = gr.Code(label="Input C Code", language="c", lines=15, value=sample_code)
            analyze_btn = gr.Button("🚀 Analyze & Fix Code", variant="primary")
        with gr.Column():
            output_report = gr.Markdown(label="Static Analysis Report")
            output_fix = gr.Markdown(label="AI Explanation & Auto-Fixed Code")
            
    analyze_btn.click(fn=code_guard_ui, inputs=input_code, outputs=[output_report, output_fix])

# Render বা অন্য সার্ভারের জন্য হোস্ট কনফিগারেশন
if __name__ == "__main__":
    demo.launch(server_name="0.0.0.0", server_port=int(os.environ.get("PORT", 7860)))
