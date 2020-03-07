# mitre-ads-notebook-templates
Jupyter notebook templates for describing the [MITRE ATT&amp;CK techniques](https://attack.mitre.org/) using Palantir's [Alerting and Detection Strategy framework](https://github.com/palantir/alerting-detection-strategy-framework). It also correlates each technique with any relevant [Sigma rules](https://github.com/Neo23x0/sigma).

### Usage

If you just want the notebooks, you can clone the repository and use the notebooks in the ```notebooks``` directory. If there are techniques missing you can rerun ```generate_notebooks.py```

```
pip install -r requirements.txt

python generate_notebooks.py
```

If you do not want the sigma notebooks just run

```
python generate_notebooks.py --no-sigma
```

### Naming scheme

There are two styles of notebooks:

1) T1234_MITRE_\<MITRE technique name\>.ipynb
2) T1234_SIGMA_\<Sigma rule name\>.ipynb

All notebook filenames begin with a MITRE ATT&CK id (e.g. T1234) and then have either MITRE or SIGMA. MITRE notebooks correspond to one MITRE ATT&CK technique (and link to all sigma rules associated with it). The Sigma files correspond to one MITRE/sigma rule combination.
