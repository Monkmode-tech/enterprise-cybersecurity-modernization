# Security Monitoring Evidence

The screenshots in this directory preserve the original controlled-lab monitoring and log-analysis workflow.

That workflow used task-specific scripts named `access-1.py`, `access-2.py`, and `apache_logs.py` with source datasets that included `access-1.log`, `access-2.log`, and `apache_logs`. Those original scripts and datasets are not included in this public repository.

[scripts/log_parser.py](../../scripts/log_parser.py) is a separate, generalized implementation developed afterward to demonstrate reusable security-log analysis. It is not the script shown in the screenshots and should not be treated as an exact reproduction of the original workflow. Public examples use synthetic data under [sample-data/](../../sample-data/) for safe, reproducible execution.
