"""Export a token classifier (the NER experiment's D3) to ONNX, and an int8 copy of it (docs/NER-EXPERIMENT.md,
"ONNX"). Runs once in an environment with torch and transformers; the files it writes need neither.

    python bench/ner/export_onnx.py MODEL_DIR OUT_DIR

OUT_DIR gets model.onnx (fp32), model.int8.onnx (dynamic int8 quantisation of the weights), the tokenizer files and
config.json, and SHA256SUMS. Nothing is downloaded: MODEL_DIR is a local snapshot."""
from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path


def main(argv: list) -> int:
    src, out = Path(argv[0]), Path(argv[1])
    out.mkdir(parents=True, exist_ok=True)
    import torch
    from onnxruntime.quantization import QuantType, quantize_dynamic
    from transformers import AutoModelForTokenClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(src, local_files_only=True)
    model = AutoModelForTokenClassification.from_pretrained(src, local_files_only=True).eval()
    enc = tok("A short text for the trace.", return_tensors="pt")
    with torch.no_grad():
        torch.onnx.export(model, (enc["input_ids"], enc["attention_mask"]), str(out / "model.onnx"),
                          input_names=["input_ids", "attention_mask"], output_names=["logits"],
                          dynamic_axes={"input_ids": {0: "batch", 1: "seq"}, "attention_mask": {0: "batch", 1: "seq"},
                                        "logits": {0: "batch", 1: "seq"}},
                          opset_version=17, dynamo=False)
    quantize_dynamic(str(out / "model.onnx"), str(out / "model.int8.onnx"), weight_type=QuantType.QInt8)
    tok.save_pretrained(out)
    shutil.copy(src / "config.json", out / "config.json")
    sums = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}" for p in sorted(out.iterdir())
            if p.is_file() and p.name != "SHA256SUMS"]
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    for line in sums:
        name = line.split()[-1]
        print(f"{name}: {(out / name).stat().st_size / 1e6:.1f} MB")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
