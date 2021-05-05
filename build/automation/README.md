## Ping all nodes in the host file
ansible -i ../hosts all -u ansible -m ping

## run ssh-agent for jump hosts
eval "$(ssh-agent -s)"
ssh-add ~/.ssh/id_rsa_setup

## run a ansible playbook in development
ansible-playbook -i dev_hosts Playbooks/elastic-stack.yml


Production NOTES

install sshpass: sudo apt-get install sshpass

To login with password based auth right after a fresh install 
ansible-playbook -i prod_hosts Playbooks/elastic-stack.yml -Kk

To run after the initial run
ansible-playbook -i prod_hosts Playbooks/elastic-stack.yml -K

