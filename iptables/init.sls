# Firewall management module
{%- if salt['pillar.get']('firewall:enabled') %}
include:
  - iptables.firewall
  - iptables.rules

{%- endif %}
