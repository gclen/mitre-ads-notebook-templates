import argparse
import logging
import re
import shutil
import subprocess
from collections import defaultdict
from pathlib import Path
from urllib.parse import urljoin

import jinja2
import nbformat as nbf
import yaml

from attackcti import attack_client

def generate_notebooks(techniques, ads_template, notebook_dir_name, mitre_sigma_mapping):

    notebook_dir = Path(notebook_dir_name)
    for technique in techniques:
        for tactic in technique['tactic']:
            tactic_display = tactic.replace('-', ' ').title()
            technique_id = technique['technique_id']
            technique_name = technique['technique']
            technique_name_normalized = re.sub(r'[\s/]+', '_', technique_name)

            url = technique['url']
            
            output_file_name = f'{technique_id}_{technique_name_normalized}.ipynb'

            references = technique['external_references']
            references = [ref for ref in references if ref['source_name'] not in ['mitre-attack', 'mitre-pre-attack']]
            
            # Get associated sigma rules if they exist
            sigma_rules = mitre_sigma_mapping.get(technique_id, [])

            out_dir = notebook_dir / tactic
            output_file = out_dir/ output_file_name
            
            if not out_dir.exists():
                out_dir.mkdir(parents=True)
            
            if output_file.exists():
                continue
            else:
                rendered = ads_template.render(tactic=tactic_display, technique=technique_name, 
                                            technique_url=url, references=references, sigma_rules=sigma_rules)
                
                nb = nbf.v4.new_notebook()
                ads_cell = nbf.v4.new_markdown_cell(rendered)
                nb['cells'] = [ads_cell]
                logging.info(f'Creating notebook {output_file}')
                nbf.write(nb, str(output_file))

def create_mitre_sigma_mapping(sigma_git_dir):
    sigma_dir = Path(sigma_git_dir)
    sigma_base_url = 'https://github.com/Neo23x0/sigma/blob/master/'
    mitre_sigma_mapping = defaultdict(list)
    attack_id_re = re.compile(r'attack\.(t[0-9]+)', flags=re.IGNORECASE)

    for rule_file in sigma_dir.glob('rules/**/*.yml'):
        # Sigma rules can have multiple sections so need to look at all of them
        with open(rule_file, 'r') as f:
            sections = list(yaml.load_all(f, Loader=yaml.FullLoader))
        
        tags = []
        # The name is a mandatory parameter so we should only see one instance of it
        rule_name = ''
        for section in sections:
            title = section.get('title', '')
            if not rule_name:
                rule_name = title
            # There may be multiple tags sections (though I haven't seen this)
            tags.extend(section.get('tags', []))
        
        rule_path = str(Path(rule_file).relative_to(sigma_dir))
        rule_url = urljoin(sigma_base_url, rule_path)
        
        for tag in tags:
            match = attack_id_re.match(tag)

            if match:
                attack_id = match.group(1).upper()
                mitre_sigma_mapping[attack_id].append({'rule_name': rule_name, 'url': rule_url})
    
    return mitre_sigma_mapping

def main():

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    parser = argparse.ArgumentParser(description='Generate a jupyter notebook for each technique in the MITRE ATT&CK framework', add_help=True)
    parser.add_argument('--output-dir', '-o', default='notebooks', help='Directory to output notebooks in')
    parser.add_argument('--no-sigma', action='store_true', help='Do not include mapping to sigma rules')
    args = parser.parse_args()

    lift = attack_client()

    logging.info('Fetching MITRE ATT&CK enterprise techniques')
    all_techniques = lift.get_enterprise_techniques(stix_format=False)
    all_techniques_no_revoked = lift.remove_revoked(all_techniques)
    logging.info(f'{len(all_techniques_no_revoked)} techniques found')

    sigma_clone_url = 'https://github.com/Neo23x0/sigma.git'
    sigma_git_dir = 'sigma_clone'
    if args.no_sigma:
        mitre_sigma_mapping = {}
    else:
        logging.info(f'Cloning sigma repository using {sigma_clone_url}')
        subprocess.run(f'git clone {sigma_clone_url} {sigma_git_dir}', shell=True)
        logging.info('Creating mapping of sigma rules to mitre techniques')
        mitre_sigma_mapping = create_mitre_sigma_mapping(sigma_git_dir)
        
        logging.info(f'Cleaning up cloned directory {sigma_git_dir}')
        shutil.rmtree(Path(sigma_git_dir))

    # Load markdown template
    template_loader = jinja2.FileSystemLoader(searchpath="./")
    template_env = jinja2.Environment(loader=template_loader)
    ads_template = template_env.get_template('ads_template.md')

    generate_notebooks(all_techniques_no_revoked, ads_template, args.output_dir, mitre_sigma_mapping)


if __name__ == '__main__':
    main()