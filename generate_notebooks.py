import argparse
import logging
import re
from pathlib import Path
import jinja2
import nbformat as nbf

from attackcti import attack_client

def generate_notebooks(techniques, ads_template, notebook_dir_name):

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
            
            out_dir = notebook_dir / tactic
            output_file = out_dir/ output_file_name
            
            if not out_dir.exists():
                out_dir.mkdir(parents=True)
            
            if output_file.exists():
                continue
            else:
                rendered = ads_template.render(tactic=tactic_display, technique=technique_name, 
                                            technique_url=url, references=references)
                
                nb = nbf.v4.new_notebook()
                ads_cell = nbf.v4.new_markdown_cell(rendered)
                nb['cells'] = [ads_cell]
                logging.info(f'Creating notebook {output_file}')
                nbf.write(nb, str(output_file))

def main():

    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    parser = argparse.ArgumentParser(description='Generate a jupyter notebook for each technique in the MITRE ATT&CK framework', add_help=True)
    parser.add_argument('--output-dir', '-o', default='notebooks', help='Directory to output notebooks in')
    # Actually parse the arguments
    args = parser.parse_args()

    lift = attack_client()

    logging.info('Fetching MITRE ATT&CK enterprise techniques')
    all_techniques = lift.get_enterprise_techniques(stix_format=False)
    all_techniques_no_revoked = lift.remove_revoked(all_techniques)
    logging.info(f'{len(all_techniques_no_revoked)} techniques found')

    # Load markdown template
    template_loader = jinja2.FileSystemLoader(searchpath="./")
    template_env = jinja2.Environment(loader=template_loader)
    ads_template = template_env.get_template('ads_template.md')

    generate_notebooks(all_techniques_no_revoked, ads_template, args.output_dir)


if __name__ == '__main__':
    main()