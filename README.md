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
Update the `Demo Job Template` to add the Controller Credential. After doing this, you can launch the projects

### Step 4 - Add Token
After successfully running the `Demo Job Template`, Update the `Automation Hub` credential with your token from https://console.redhat.com/ansible/automation-hub/token

### Step 5 - Sync Project
Sync the `Ansible official demo project`. Once successful, follow instructions to deploy demos from [here](https://github.com/RedHatGov/product-demos#using-this-project)
