# Top 100 HuggingFace Models - Security Scan Report

**Scan Date:** 2026-08-22T23:44:43.330972+00:00
**Duration:** 1333.8s
**Models Scanned:** 100/100
**Total Findings:** 83
**Total Data Fetched:** 157.37 MB

## Findings by Severity

| Severity | Count |
|----------|-------|
| 🔴 CRITICAL | 70 |
| 🟠 HIGH | 3 |
| 🟡 MEDIUM | 1 |
| 🔵 LOW | 9 |
| ⚪ INFO | 0 |

## Risk Distribution

| Risk Level | Models |
|------------|--------|
| CRITICAL | 6 |
| HIGH | 29 |
| MEDIUM | 1 |
| LOW | 64 |

## ⚠️ Models Flagged as Potentially Malicious: 37

- **sentence-transformers/all-MiniLM-L6-v2** (risk: 44/100)
- **cross-encoder/ms-marco-MiniLM-L6-v2** (risk: 40/100)
- **BAAI/bge-small-en-v1.5** (risk: 40/100)
- **sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2** (risk: 40/100)
- **BAAI/bge-m3** (risk: 80/100)
- **lpiccinelli/unidepth-v2-vitl14** (risk: 40/100)
- **sentence-transformers/all-mpnet-base-v2** (risk: 44/100)
- **openai/clip-vit-base-patch32** (risk: 40/100)
- **timm/mobilenetv3_small_100.lamb_in1k** (risk: 40/100)
- **facebook/opt-125m** (risk: 40/100)
- **BAAI/bge-large-en-v1.5** (risk: 40/100)
- **hexgrad/Kokoro-82M** (risk: 40/100)
- **intfloat/multilingual-e5-small** (risk: 40/100)
- **BAAI/bge-base-en-v1.5** (risk: 40/100)
- **argmaxinc/whisperkit-coreml** (risk: 100/100)
- **Comfy-Org/stable-diffusion-v1-5-archive** (risk: 37/100)
- **sentence-transformers/paraphrase-multilingual-mpnet-base-v2** (risk: 40/100)
- **Bingsu/adetailer** (risk: 100/100)
- **coqui/XTTS-v2** (risk: 100/100)
- **cross-encoder/ms-marco-MiniLM-L4-v2** (risk: 40/100)
- **facebook/contriever** (risk: 40/100)
- **jonatasgrosman/wav2vec2-large-xlsr-53-japanese** (risk: 40/100)
- **laion/clap-htsat-fused** (risk: 40/100)
- **intfloat/multilingual-e5-large** (risk: 40/100)
- **pyannote/wespeaker-voxceleb-resnet34-LM** (risk: 40/100)
- **openai/clip-vit-large-patch14** (risk: 40/100)
- **Comfy-Org/z_image_turbo** (risk: 15/100)
- **intfloat/multilingual-e5-base** (risk: 40/100)
- **answerdotai/ModernBERT-base** (risk: 40/100)
- **jonatasgrosman/wav2vec2-large-xlsr-53-portuguese** (risk: 50/100)
- **ibm-granite/granite-embedding-small-english-r2** (risk: 40/100)
- **microsoft/mdeberta-v3-base** (risk: 80/100)
- **facebook/dinov2-small** (risk: 40/100)
- **google/vit-base-patch16-224** (risk: 40/100)
- **BAAI/bge-small-zh-v1.5** (risk: 40/100)
- **openai/whisper-large-v3** (risk: 100/100)
- **nomic-ai/nomic-embed-text-v1** (risk: 40/100)

## Per-Model Results (sorted by risk)

| # | Model | Risk | Findings | Duration | Data |
|---|-------|------|----------|----------|------|
| 1 | `argmaxinc/whisperkit-coreml` | 100/100 (CRITICAL) | 5 | 196789ms | 42350.8 KB |
| 2 | `Bingsu/adetailer` | 100/100 (CRITICAL) | 26 | 11101ms | 6144.0 KB |
| 3 | `coqui/XTTS-v2` | 100/100 (CRITICAL) | 3 | 3426ms | 1541.3 KB |
| 4 | `openai/whisper-large-v3` | 100/100 (CRITICAL) | 3 | 8029ms | 2109.9 KB |
| 5 | `BAAI/bge-m3` | 80/100 (CRITICAL) | 2 | 3292ms | 1030.6 KB |
| 6 | `microsoft/mdeberta-v3-base` | 80/100 (CRITICAL) | 2 | 3419ms | 1024.6 KB |
| 7 | `jonatasgrosman/wav2vec2-large-xlsr-53-portuguese` | 50/100 (HIGH) | 6 | 3653ms | 519.8 KB |
| 8 | `sentence-transformers/all-MiniLM-L6-v2` | 44/100 (HIGH) | 3 | 4396ms | 1561.1 KB |
| 9 | `sentence-transformers/all-mpnet-base-v2` | 44/100 (HIGH) | 3 | 4629ms | 1571.3 KB |
| 10 | `cross-encoder/ms-marco-MiniLM-L6-v2` | 40/100 (HIGH) | 1 | 4277ms | 1549.9 KB |
| 11 | `BAAI/bge-small-en-v1.5` | 40/100 (HIGH) | 1 | 2794ms | 535.0 KB |
| 12 | `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2` | 40/100 (HIGH) | 1 | 4280ms | 1559.3 KB |
| 13 | `lpiccinelli/unidepth-v2-vitl14` | 40/100 (HIGH) | 1 | 2829ms | 573.8 KB |
| 14 | `openai/clip-vit-base-patch32` | 40/100 (HIGH) | 1 | 1571ms | 516.7 KB |
| 15 | `timm/mobilenetv3_small_100.lamb_in1k` | 40/100 (HIGH) | 1 | 2540ms | 533.8 KB |
| 16 | `facebook/opt-125m` | 40/100 (HIGH) | 1 | 2032ms | 513.4 KB |
| 17 | `BAAI/bge-large-en-v1.5` | 40/100 (HIGH) | 1 | 3700ms | 557.2 KB |
| 18 | `hexgrad/Kokoro-82M` | 40/100 (HIGH) | 1 | 47364ms | 28116.6 KB |
| 19 | `intfloat/multilingual-e5-small` | 40/100 (HIGH) | 1 | 4791ms | 1048.3 KB |
| 20 | `BAAI/bge-base-en-v1.5` | 40/100 (HIGH) | 1 | 3233ms | 535.2 KB |
| 21 | `sentence-transformers/paraphrase-multilingual-mpnet-base-v2` | 40/100 (HIGH) | 1 | 5013ms | 1559.3 KB |
| 22 | `cross-encoder/ms-marco-MiniLM-L4-v2` | 40/100 (HIGH) | 1 | 5002ms | 1546.3 KB |
| 23 | `facebook/contriever` | 40/100 (HIGH) | 1 | 1814ms | 512.9 KB |
| 24 | `jonatasgrosman/wav2vec2-large-xlsr-53-japanese` | 40/100 (HIGH) | 1 | 1417ms | 513.5 KB |
| 25 | `laion/clap-htsat-fused` | 40/100 (HIGH) | 1 | 3336ms | 578.3 KB |
| 26 | `intfloat/multilingual-e5-large` | 40/100 (HIGH) | 1 | 5745ms | 1070.8 KB |
| 27 | `pyannote/wespeaker-voxceleb-resnet34-LM` | 40/100 (HIGH) | 1 | 980ms | 512.0 KB |
| 28 | `openai/clip-vit-large-patch14` | 40/100 (HIGH) | 1 | 2639ms | 587.5 KB |
| 29 | `intfloat/multilingual-e5-base` | 40/100 (HIGH) | 1 | 4657ms | 1048.4 KB |
| 30 | `answerdotai/ModernBERT-base` | 40/100 (HIGH) | 1 | 2850ms | 547.3 KB |
| 31 | `ibm-granite/granite-embedding-small-english-r2` | 40/100 (HIGH) | 1 | 4952ms | 540.8 KB |
| 32 | `facebook/dinov2-small` | 40/100 (HIGH) | 1 | 2586ms | 535.6 KB |
| 33 | `google/vit-base-patch16-224` | 40/100 (HIGH) | 1 | 3462ms | 602.7 KB |
| 34 | `BAAI/bge-small-zh-v1.5` | 40/100 (HIGH) | 1 | 3807ms | 521.0 KB |
| 35 | `nomic-ai/nomic-embed-text-v1` | 40/100 (HIGH) | 1 | 4199ms | 526.7 KB |
| 36 | `Comfy-Org/stable-diffusion-v1-5-archive` | 37/100 (MEDIUM) | 3 | 4284ms | 501.3 KB |
| 37 | `Comfy-Org/z_image_turbo` | 15/100 (LOW) | 1 | 13776ms | 586.3 KB |
| 38 | `google-bert/bert-base-uncased` | 0/100 (LOW) | 0 | 3404ms | 1048.1 KB |
| 39 | `google/electra-base-discriminator` | 0/100 (LOW) | 0 | 1843ms | 512.7 KB |
| 40 | `amazon/chronos-2` | 0/100 (LOW) | 0 | 1559ms | 20.4 KB |
| 41 | `Qwen/Qwen3-0.6B` | 0/100 (LOW) | 0 | 1989ms | 45.2 KB |
| 42 | `google-t5/t5-small` | 0/100 (LOW) | 0 | 3014ms | 530.8 KB |
| 43 | `BAAI/bge-reranker-v2-m3` | 0/100 (LOW) | 0 | 1658ms | 49.5 KB |
| 44 | `FacebookAI/xlm-roberta-base` | 0/100 (LOW) | 0 | 2855ms | 536.6 KB |
| 45 | `Comfy-Org/MiniMax-H3` | 0/100 (LOW) | 0 | 32179ms | 1730.0 KB |
| 46 | `nomic-ai/nomic-embed-text-v1.5` | 0/100 (LOW) | 0 | 2156ms | 15.2 KB |
| 47 | `trl-internal-testing/tiny-Qwen2ForCausalLM-2.5` | 0/100 (LOW) | 0 | 2474ms | 8.2 KB |
| 48 | `Qwen/Qwen3-8B` | 0/100 (LOW) | 0 | 6564ms | 55.4 KB |
| 49 | `openai-community/gpt2` | 0/100 (LOW) | 0 | 4096ms | 528.0 KB |
| 50 | `Qwen/Qwen3.5-9B` | 0/100 (LOW) | 0 | 5438ms | 111.6 KB |
| 51 | `Qwen/Qwen3.6-35B-A3B-FP8` | 0/100 (LOW) | 0 | 54520ms | 8717.4 KB |
| 52 | `nvidia/Qwen3.6-35B-A3B-NVFP4` | 0/100 (LOW) | 0 | 8387ms | 16438.0 KB |
| 53 | `unsloth/Qwen3-Coder-30B-A3B-Instruct-GGUF` | 0/100 (LOW) | 0 | 208ms | 0.0 KB |
| 54 | `Qwen/Qwen2.5-7B-Instruct` | 0/100 (LOW) | 0 | 5795ms | 46.0 KB |
| 55 | `FacebookAI/roberta-base` | 0/100 (LOW) | 0 | 3117ms | 536.1 KB |
| 56 | `FacebookAI/roberta-large` | 0/100 (LOW) | 0 | 2897ms | 559.5 KB |
| 57 | `pyannote/speaker-diarization-3.1` | 0/100 (LOW) | 0 | 301ms | 0.0 KB |
| 58 | `Qwen/Qwen2.5-1.5B-Instruct` | 0/100 (LOW) | 0 | 1901ms | 45.6 KB |
| 59 | `Qwen/Qwen3.6-27B-FP8` | 0/100 (LOW) | 0 | 81506ms | 265.6 KB |
| 60 | `Qwen/Qwen2.5-VL-7B-Instruct` | 0/100 (LOW) | 0 | 6249ms | 86.5 KB |
| 61 | `google/gemma-4-26B-A4B-it` | 0/100 (LOW) | 0 | 3375ms | 141.2 KB |
| 62 | `google/gemma-4-31B-it` | 0/100 (LOW) | 0 | 3231ms | 164.5 KB |
| 63 | `autogluon/chronos-bolt-small` | 0/100 (LOW) | 0 | 1562ms | 17.5 KB |
| 64 | `meta-llama/Llama-3.2-1B-Instruct` | 0/100 (LOW) | 0 | 960ms | 0.0 KB |
| 65 | `openai/whisper-large-v3-turbo` | 0/100 (LOW) | 0 | 2188ms | 348.2 KB |
| 66 | `Qwen/Qwen3.5-4B` | 0/100 (LOW) | 0 | 3067ms | 107.5 KB |
| 67 | `openai/gpt-oss-20b` | 0/100 (LOW) | 0 | 7486ms | 604.7 KB |
| 68 | `Qwen/Qwen2.5-3B-Instruct` | 0/100 (LOW) | 0 | 3626ms | 56.5 KB |
| 69 | `Qwen/Qwen3-Embedding-0.6B` | 0/100 (LOW) | 0 | 3641ms | 43.2 KB |
| 70 | `distilbert/distilbert-base-uncased` | 0/100 (LOW) | 0 | 2739ms | 524.9 KB |
| 71 | `farbodtavakkoli/OTel-2.0-LLM-31B-IT` | 0/100 (LOW) | 0 | 20099ms | 100.7 KB |
| 72 | `Qwen/Qwen2.5-0.5B-Instruct` | 0/100 (LOW) | 0 | 2022ms | 39.5 KB |
| 73 | `meta-llama/Llama-3.1-8B-Instruct` | 0/100 (LOW) | 0 | 3350ms | 0.0 KB |
| 74 | `Qwen/Qwen3.6-27B` | 0/100 (LOW) | 0 | 19232ms | 167.7 KB |
| 75 | `unsloth/Qwen3.8-27B-GGUF` | 0/100 (LOW) | 0 | 1490ms | 3.7 KB |
| 76 | `Qwen/Qwen2.5-VL-3B-Instruct` | 0/100 (LOW) | 0 | 4074ms | 97.0 KB |
| 77 | `pyannote/segmentation-3.0` | 0/100 (LOW) | 0 | 451ms | 0.0 KB |
| 78 | `autogluon/chronos-2` | 0/100 (LOW) | 0 | 2153ms | 20.4 KB |
| 79 | `deepseek-ai/DeepSeek-R1` | 0/100 (LOW) | 0 | 236322ms | 11698.7 KB |
| 80 | `Qwen/Qwen3.6-35B-A3B` | 0/100 (LOW) | 0 | 32920ms | 148.4 KB |
| 81 | `FacebookAI/xlm-roberta-large` | 0/100 (LOW) | 0 | 4854ms | 561.6 KB |
| 82 | `google/gemma-4-E4B-it` | 0/100 (LOW) | 0 | 2989ms | 282.7 KB |
| 83 | `pyannote/speaker-diarization-community-1` | 0/100 (LOW) | 0 | 1571ms | 0.0 KB |
| 84 | `Qwen/Qwen3-VL-8B-Instruct` | 0/100 (LOW) | 0 | 6184ms | 102.3 KB |
| 85 | `Qwen/Qwen3-1.7B` | 0/100 (LOW) | 0 | 3231ms | 45.4 KB |
| 86 | `Qwen/Qwen3-4B` | 0/100 (LOW) | 0 | 4446ms | 55.2 KB |
| 87 | `Comfy-Org/Wan_2.2_ComfyUI_Repackaged` | 0/100 (LOW) | 0 | 61593ms | 5753.0 KB |
| 88 | `google/gemma-3-1b-it` | 0/100 (LOW) | 0 | 3193ms | 0.0 KB |
| 89 | `amazon/chronos-bolt-small` | 0/100 (LOW) | 0 | 1660ms | 17.5 KB |
| 90 | `openai/gpt-oss-120b` | 0/100 (LOW) | 0 | 25331ms | 647.1 KB |
| 91 | `ProsusAI/finbert` | 0/100 (LOW) | 0 | 2236ms | 513.0 KB |
| 92 | `ornith-ai/Ornith-1.0-9B-GGUF` | 0/100 (LOW) | 0 | 179ms | 0.0 KB |
| 93 | `Qwen/Qwen3-ASR-1.7B` | 0/100 (LOW) | 0 | 6093ms | 103.0 KB |
| 94 | `dphn/dolphin-2.9.1-yi-1.5-34b` | 0/100 (LOW) | 0 | 22940ms | 64.5 KB |
| 95 | `meta-llama/Prompt-Guard-86M` | 0/100 (LOW) | 0 | 724ms | 0.0 KB |
| 96 | `Qwen/Qwen2.5-7B-Instruct-AWQ` | 0/100 (LOW) | 0 | 4440ms | 88.6 KB |
| 97 | `datasocietyco/bge-base-en-v1.5-course-recommender-v5` | 0/100 (LOW) | 0 | 2638ms | 24.1 KB |
| 98 | `google-bert/bert-base-multilingual-uncased` | 0/100 (LOW) | 0 | 3750ms | 536.2 KB |
| 99 | `pyannote/voice-activity-detection` | 0/100 (LOW) | 0 | 159ms | 0.0 KB |
| 100 | `pyannote/segmentation` | 0/100 (LOW) | 0 | 628ms | 0.0 KB |

---
*Generated by hf-model-provenance-scanner v1.0.0 at 2026-08-22T23:44:43.330972+00:00*
