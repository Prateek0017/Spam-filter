# bec-guard

Tiered spam / phishing / BEC filter for a B2B email platform. *(Work in progress, full README in the final phase.)*

```bash
make setup && make data train   # then: make eval | make demo
```

**macOS:** LightGBM needs the OpenMP runtime. Install it once with `brew install libomp`, otherwise
importing LightGBM fails with `Library not loaded: @rpath/libomp.dylib`.

Evaluation results: [reports/eval_report.md](reports/eval_report.md).
