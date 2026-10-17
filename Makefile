# bec-guard: common entry points. All targets are reproducible (seeded).
PY      ?= .venv/bin/python
CONFIG  ?= configs/default.yaml

.PHONY: setup data train eval multiseed demo test all clean

setup:            ## Create Python 3.11 venv and install deps (requires uv; macOS also: brew install libomp)
	uv venv --python 3.11 .venv
	uv pip install --python $(PY) -r requirements-dev.txt

data:             ## Generate synthetic tenants, threat intel and ~10k labelled emails
	$(PY) -m src.data.generate --config $(CONFIG)

train:            ## Build point-in-time features, train text model + LightGBM
	$(PY) -m src.models.train --config $(CONFIG)

eval:             ## Metrics, SHAP, ablation, latency + cost reports, OOD check -> reports/
	$(PY) -m src.eval.report --config $(CONFIG)
	$(PY) -m src.eval.ood --config $(CONFIG)

multiseed:        ## Whole pipeline over 5 seeds -> reports/multiseed.md (mean ± std, ~3 minutes)
	$(PY) -m src.eval.multiseed --config $(CONFIG)

demo:             ## Streamlit demo on :8501
	$(PY) -m streamlit run demo/streamlit_app.py

test:
	$(PY) -m pytest

all: data train eval test

clean:
	rm -rf data/raw/* data/processed/* models/ reports/*.png reports/*.md
