# ansible-tower-samples
Ansible Tower Playbook Samples

## Setting up Product Demos

### Step 1 - Create a Credential
Create a new credential with the following parameters
|      |                       |
|------|-----------------------|
| Name | 'Controller Credential' |
| Organization | 'Default' |
| Credential Type | 'Red Hat Ansible Automation Platform' |
| Red Hat Ansible Automation Platform | URL to access Controller |
| Username | 'admin' |
| Password | Use Admin Password |

### Step 2 - Change Project
Update the `Demo Project` with the following parameters
|      |                       |
|------|-----------------------|
| Source Control URL | 'https://github.com/RedHatGov/ansible-tower-samples' |
| Source Control Branch/Tag/Commit | 'product-demos' |

### Step 3 - Update Job Template
Update the `Demo Job Template` to add the Controller Credential and select `product_demos.yml` as the playbook to run. After doing this, you can launch the job template.

This playbook with create the following setup in your Controller:

- Create `Workshop Credential` for machine authentication
- Create `Automation Hub` credential for sourcing certified collections
- Add the `Automation Hub` credential to the `Default` organization
- Create the `Ansible official demo project` to source the product demo playbooks
- Create the `Workshop Inventory` for hosts and dynamic inventory sources
- Set the default execution environment

> **_NOTE:_** The names of credentials, projects, inventories, etc. are specific and case sensitive. Changing the value described here may cause your demos to fail installation.

### Step 4 - Post Job Setup
After successfully running the `Demo Job Template`, Update the `Automation Hub` credential with your token from https://console.redhat.com/ansible/automation-hub/token

Update the `Workshop Credential` with login information for your hosts.

Add hosts to the `Workshop Inventory` that you would like to automate.

> **_NOTE:_** Re-running the `Demo Job Template` will replace the `Automation Hub` credential  and `Workshop Credential` with default values. Always update the token after running the job template.

### Step 5 - Sync Project
Sync the `Ansible official demo project`. Once successful, follow instructions to deploy demos from [here](https://github.com/RedHatGov/product-demos#using-this-project)
