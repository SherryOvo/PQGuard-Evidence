export ROOT=/root/autodl-tmp/pqguard_review_strengthening_20261124
export OLD=/root/autodl-tmp/pqguard_gpu_batch_20261123
export PYTHON=$OLD/venv/bin/python
export PATH=$OLD/venv/bin:$PATH
export OQS_INSTALL_PATH=$OLD/oqs_install
export LD_LIBRARY_PATH=$OQS_INSTALL_PATH/lib:${LD_LIBRARY_PATH:-}
export PYTHONPATH=$ROOT/vendor:$ROOT/scripts:$ROOT/vendor/deps
export PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
export HF_HOME=$ROOT/work/hf_cache TRANSFORMERS_OFFLINE=1 HF_HUB_OFFLINE=1
export VLLM_CACHE_ROOT=$ROOT/work/vllm_cache CUDA_CACHE_PATH=$ROOT/work/cuda_cache
export TOKENIZERS_PARALLELISM=false
export VLLM_USE_V1=1 VLLM_NO_USAGE_STATS=1 DO_NOT_TRACK=1
export TRITON_CACHE_DIR=$ROOT/work/triton_cache TMPDIR=$ROOT/work/tmp
