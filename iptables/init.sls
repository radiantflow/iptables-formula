# Firewall management module
{%- if salt['pillar.get']('firewall:enabled') %}
  {% set firewall = salt['pillar.get']('firewall', {}) %}
  {% set install = firewall.get('install', False) %}
  {% set strict_mode = firewall.get('strict', False) %}
  {% set global_block_nomatch = firewall.get('block_nomatch', False) %}
  {% set packages = salt['grains.filter_by']({
    'Debian': ['iptables', 'iptables-persistent'],
    'RedHat': ['iptables'],
    'default': 'Debian'}) %}

    {%- if install %}
      # Install required packages for firewalling      
      iptables_packages:
        pkg.installed:
          - pkgs:
            {%- for pkg in packages %}
            - {{pkg}}
            {%- endfor %}
    {%- endif %}

    {%- if strict_mode %}
      # If the firewall is set to strict mode, we'll need to allow some 
      # that always need access to anything
      iptables_allow_localhost:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: 127.0.0.1
          - save: True

      # Allow related/established sessions
      iptables_allow_established:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - match: conntrack
          - ctstate: 'RELATED,ESTABLISHED'
          - save: True            

      # Set the policy to deny everything unless defined
      enable_reject_policy:
        iptables.set_policy:
          - table: filter
          - chain: INPUT
          - policy: DROP
          - require:
            - iptables: iptables_allow_localhost
            - iptables: iptables_allow_established
    {%- endif %}

  # Generate ipsets for all services that we have information about
  {%- for service_name, service_details in firewall.get('services', {}).items() %}  
    {% set block_nomatch = service_details.get('block_nomatch', False) %}
    {% set interfaces = service_details.get('interfaces','') %}
    {% set protos = service_details.get('protos',['tcp']) %}
    {% if service_details.get('comment', False) %}
      {% set comment = '- comment: ' + service_details.get('comment') %}
    {% else %}
      {% set comment = '' %}
    {% endif %}

    # Allow rules for ips/subnets
    {%- for ip in service_details.get('ips_allow', []) %}
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{ip}}_{{proto}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          {{ comment }}
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_{{service_name}}_allow_{{ip}}_{{proto}}_{{interface}}:
        iptables.append:
          - table: filter
          - chain: INPUT
          - jump: ACCEPT
          - i: {{ interface }}
          - source: {{ ip }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          {{ comment }}
          {%- endfor %}
        {%- endfor %}
      {%- endif %}
    {%- endfor %}

    {%- if not strict_mode and global_block_nomatch or block_nomatch %}
      # If strict mode is disabled we may want to block anything else
      {%- if interfaces == '' %}
        {%- for proto in protos %}
      iptables_{{service_name}}_deny_other_{{proto}}:
        iptables.append:
          - position: last
          - table: filter
          - chain: INPUT
          - jump: REJECT
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          {{ comment }}
        {%- endfor %}
      {%- else %}
        {%- for interface in interfaces %}
          {%- for proto in protos %}
      iptables_{{service_name}}_deny_other_{{proto}}_{{interface}}:
        iptables.append:
          - position: last
          - table: filter
          - chain: INPUT
          - jump: REJECT
          - i: {{ interface }}
          - dport: {{ service_name }}
          - proto: {{ proto }}
          - save: True
          {{ comment }}
          {%- endfor %}
        {%- endfor %}
      {%- endif %}

    {%- endif %}    

  {%- endfor %}

  # Generate rules for Chain rules (from salt-formula-iptables)
  {%- for chain_name, chain in firewall.get('chain', {}).iteritems() %}

    iptables_{{ chain_name }}:
      iptables.chain_present:
        - family: ipv4
        - name: {{ chain_name }}
        - table: filter
        - require:
          - pkg: iptables_packages

    {%- if grains.ipv6|default(False) and firewall.ipv6|default(True) %}
    iptables_{{ chain_name }}_ipv6:
      iptables.chain_present:
        - family: ipv6
        - name: {{ chain_name }}
        - table: filter
        - require:
          - pkg: iptables_packages
    {%- if chain.policy is defined %}
        - require_in:
          - iptables: iptables_{{ chain_name }}_ipv6_policy
    {%- endif  %}
    {%- endif %}

    {%- if chain.policy is defined %}
    iptables_{{ chain_name }}_policy:
      iptables.set_policy:
        - family: ipv4
        - chain: {{ chain_name }}
        - policy: {{ chain.policy }}
        - table: filter
        - require:
          - iptables: iptables_{{ chain_name }}

      {%- if grains.ipv6|default(False) and firewall.ipv6|default(True) %}
    iptables_{{ chain_name }}_ipv6_policy:
      iptables.set_policy:
        - family: ipv6
        - chain: {{ chain_name }}
        - policy: {{ chain.policy }}
        - table: filter
        - require:
          - iptables: iptables_{{ chain_name }}_ipv6
      {%- endif %}
    {%- endif %}

    {%- for service_name, service in pillar.items() %}
      {%- if service is mapping and service.get('_support', {}).get('iptables', {}).get('enabled', False) %}

        {%- set grains_fragment_file = service_name+'/meta/iptables.yml' %}
        {%- macro load_grains_file() %}{% include grains_fragment_file %}{% endmacro %}
        {%- set grains_yaml = load_grains_file()|load_yaml %}

        {%- for rule in grains_yaml.iptables.rules %}
          {%- set rule_name = service_name+'_'+loop.index|string %}
          {% include "iptables/_rule.sls" %}
        {%- endfor %}
      {%- endif %}
    {%- endfor %}

    {%- for rule in chain.get('rules', []) %}
      {%- set rule_name = loop.index %}
      {% include "iptables/_rule.sls" %}
    {%- endfor %}

    {%- endfor %}

{%- endif %}
