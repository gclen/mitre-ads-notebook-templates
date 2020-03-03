## Goal

## Categorization
[{{ tactic }}/{{ technique }}]({{ technique_url }})

## Strategy Abstract

## Technical Context

## Blind Spots and Assumptions

## False Positives

## Priority

## Validation

## Response

## Additional Resources
{% for ref in references %}
 - [{{ ref['source_name'] }}]({{ ref['url'] }})
{% endfor %}

{% if sigma_rules %}
#### Related sigma rules
{% for rule in sigma_rules %}
- [{{ rule['rule_name'] }}]({{ rule['url'] }})
{% endfor %}
{% endif %}
