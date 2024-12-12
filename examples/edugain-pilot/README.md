
This directory contains a setup for a (small) edugain-like federation 
(without OPs).

To getting the testbed up and running do the following from this directory 
(which must be named `edugain-pilot`):

```bash
# Create some needed empty directories
./init-directories.sh
# Change domain names
./update-domains.sh <your_base_domain>
# Generate a refeds trust mark owner jwks and issue delegation jwt and update the config files
./insert-delegation.sh
# Start up the containers
docker-compose up -d
# Add suboridnates to authorities
./connect-federation.sh
# Entitle entities to be able to obtain trust marks.
./entitle-trustmarks.sh
```

For more information, please refer to the different scripts and config files.