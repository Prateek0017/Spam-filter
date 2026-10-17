# bec-guard: common entry points. All targets are reproducible (seeded).
PY      ?= .venv/bin/python
CONFIG  ?= configs/default.yaml

.PHONY: setup data train eval bench api demo test notebook docker all clean

setup:            ## Create Python 3.11 venv and install deps (requires uv)
	uv venv --python 3.11 .venv
	uv pip install --python $(PY) -r requirements-dev.txt

data:             ## Generate synthetic tenants, history and ~25k labelled emails
	$(PY) -m src.data.generate --config $(CONFIG)

train:            ## Train text model, LightGBM classifier and local intent head
	$(PY) -m src.models.train --config $(CONFIG)

eval:             ## Metrics, thresholds, SHAP, ablation, latency + cost reports -> reports/
	$(PY) -m src.eval.report --config $(CONFIG)

bench:            ## Latency benchmark only
	$(PY) -m src.eval.latency_bench --config $(CONFIG)

api:              ## FastAPI service on :8000 (POST /classify)
	$(PY) -m uvicorn app.main:app --host 0.0.0.0 --port 8000

demo:             ## Streamlit demo on :8501
	$(PY) -m streamlit run demo/streamlit_app.py

test:
	$(PY) -m pytest

notebook:         ## Execute the EDA + training notebook in place (outputs saved)
	$(PY) -m jupyter nbconvert --to notebook --execute --inplace notebooks/eda_and_training.ipynb

docker:
	docker build -t bec-guard .

all: data train eval test

clean:
	rm -rf data/raw/* data/processed/* models/ reports/*.png reports/*.md
