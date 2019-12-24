##############################################################################################################################
#
#
#
##############################################################################################################################

# See also https://docs.microsoft.com/en-us/azure/cloud-adoption-framework/ready/considerations/naming-and-tagging

az --version
az account list 
az account show 

# /!\ In CloudShell, the default subscription is not always the one you thought ...
subName="set here the name of your subscription"

subName=$(az account list --query "[?name=='${subName}'].{name:name}"  --output tsv)
echo "subscription Name :" $subName 
subId=$(az account list --query "[?name=='${subName}'].{id:id}"  --output tsv)
echo "subscription ID :" $subId

az account set --subscription $subId
az account show 

# az account list-locations : francecentral | northeurope | westeurope
location=northeurope 
echo "location is : " $location 

appName="fmi" 
echo "appName is : " $appName 

dnz_zone="cloudapp.net" # azurewebsites.net 
echo "DNS Zone is : " $dnz_zone

custom_dns="fff.fr"

# Storage account name must be between 3 and 24 characters in length and use numbers and lower-case letters only
storage_name="stne""${appName,,}"
echo "Storage name:" $storage_name


# original sources at https://github.com/spring-projects/spring-petclinic.git then forked to https://github.com/spring-petclinic
# forks project on your GitHub account
# https://stackoverflow.com/questions/31939849/spring-boot-default-log-location
# https://spring-petclinic.github.io/docs/forks.html
git_url="https://github.com/spring-projects/spring-petclinic.git"
echo "Project git repo URL : " $git_url 

version=$(az aks get-versions -l $location --query 'orchestrators[-1].orchestratorVersion' -o tsv) 
echo "version is :" $version 

network_plugin="azure"
echo "Network Plugin is : " $network_plugin 

network_policy="azure"
echo "Network Policy is : " $network_policy 

rg_name="rg-${appName}-${location}" 
echo "RG name:" $rg_name 

target_namespace="staging"
echo "Target namespace:" $target_namespace

cluster_name="aks-${appName}-${target_namespace}-101" #aks-<App Name>-<Environment>-<###>
echo "Cluster name:" $cluster_name

appgwName="ingress-appgw"
echo "App Gateway name:" $appgwName

# --nodepool-name can contain at most 12 characters. must conform to the following pattern: '^[a-z][a-z0-9]{0,11}$'.
node_pool_name="devnodepool"
echo "Node Pool name:" $node_pool_name

vnet_name="vnet-${appName}"
echo "VNet Name :" $vnet_name

subnet_name="snet-${appName}"
echo "Subnet Name :" $subnet_name

vault_name="vault-${appName}"
echo "Vault name :" $vault_name

vault_secret="NoSugarNoStar" 
echo "Vault secret:" $vault_secret 

analytics_workspace_name="${appName}AnalyticsWorkspace"
echo "Analytics Workspace Name :" $analytics_workspace_name

acr_registry_name="acr${appName,,}"
echo "ACR registry Name :" $acr_registry_name


##############################################################################################################################
#
# Create service Principal
#
##############################################################################################################################

# https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-create-service-principal-portal
# https://docs.microsoft.com/en-us/cli/azure/ad/sp?view=azure-cli-latest#az-ad-sp-create-for-rbac
# https://docs.microsoft.com/en-us/cli/azure/create-an-azure-service-principal-azure-cli?view=azure-cli-latest
# As of Azure CLI 2.0.68, the --password parameter to create a service principal with a user-defined password is no longer supported to prevent the accidental use of weak passwords.
sp_password=$(az ad sp create-for-rbac --name $appName --role contributor --query password --output tsv)  #  --keyvault $vault_name --create-cert --cert "${appName}-Certificate"
echo $sp_password > spp.txt
echo "Service Principal Password saved to ./spp.txt. IMPORTANT Keep your password ..." 
# sp_password=`cat spp.txt`
sp_id=$(az ad sp list --show-mine --query "[?appDisplayName=='${appName}'].{appId:appId}" --output tsv)
echo "Service Principal ID:" $sp_id 
echo $sp_id > spid.txt
az ad sp show --id $sp_id

# Get the id of the service principal configured for AKS
CLIENT_ID=$(az aks show --resource-group $AKS_RESOURCE_GROUP --name $AKS_CLUSTER_NAME --query "servicePrincipalProfile.clientId" --output tsv)
echo "CLIENT_ID:" $CLIENT_ID 

##############################################################################################################################
#
# Create RG & Networks
#
##############################################################################################################################
az group create --name $rg_name-$location --location $location
# https://docs.microsoft.com/en-us/cli/azure/storage/account?view=azure-cli-latest#az-storage-account-create
# https://docs.microsoft.com/en-us/azure/storage/common/storage-introduction#types-of-storage-accounts
az storage account create --name $storage_name --kind StorageV2 --sku Standard_LRS --resource-group $rg_name  --location $location --https-only true

az network vnet create --name $vnet_name --resource-group $rg_name --address-prefixes 172.16.0.0/16 --location $location
az network vnet subnet create --name $subnet_name --address-prefixes 172.16.1.0/24 --vnet-name $vnet_name --resource-group $rg_name 

vnet_id=$(az network vnet show --resource-group $rg_name --name  $vnet_name --query id -o tsv)
subnet_id=$(az network vnet subnet show --resource-group $rg_name --vnet-name  $vnet_name  --name $subnet_name --query id -o tsv)
echo "VNet Id :" $vnet_id	
echo "Subnet Id :" $subnet_id	
        

##############################################################################################################################
#
# Create Cluster. For Basic/Advcanced networking options, see https://docs.microsoft.com/en-us/azure/aks/configure-kubenet
#
##############################################################################################################################
az aks create --name $cluster_name \
    --resource-group $rg_name \
    --service-principal $sp_id \
    --client-secret $sp_password \
    --zones 1 2 3 \
    --vnet-subnet-id $subnet_id \
    --service-cidr 10.0.0.0/16 \
    --dns-service-ip 10.0.0.10 \
    --location $location \
    --kubernetes-version $version \
    --node-count 3 \
    --generate-ssh-keys \
    --network-plugin $network_plugin \
    --network-policy $network_policy \
    --nodepool-name  $node_pool_name \
    --verbose \
    --load-balancer-sku standard \
    --vm-set-type VirtualMachineScaleSets

az aks get-credentials --resource-group $rg_name  --name $cluster_name

# https://kubernetes.io/docs/reference/kubectl/cheatsheet/
alias k=kubectl
complete -F __start_kubectl k
kubectl cluster-info
kubectl config view

# Namespaces
kubectl create namespace development
kubectl label namespace/development purpose=development

kubectl create namespace staging
kubectl label namespace/staging purpose=staging

kubectl create namespace production
kubectl label namespace/production purpose=production

kubectl describe namespace production

# Play
kubectl get nodes

# https://docs.microsoft.com/en-us/azure/aks/availability-zones#verify-node-distribution-across-zones
kubectl describe nodes | grep -e "Name:" -e "failure-domain.beta.kubernetes.io/zone"

kubectl get pods
kubectl top node
kubectl api-resources --namespaced=true
kubectl api-resources --namespaced=false

kubectl get roles --all-namespaces
kubectl get serviceaccounts --all-namespaces
kubectl get rolebindings --all-namespaces
kubectl get ingresses  --all-namespaces

# Monitor
az aks enable-addons --resource-group $rg_name --name $cluster_name --addons monitoring

# https://docs.microsoft.com/en-us/azure/aks/kubernetes-dashboard
kubectl create clusterrolebinding kubernetes-dashboard --clusterrole=cluster-admin --serviceaccount=kube-system:kubernetes-dashboard
az aks browse --resource-group $rg_name --name $cluster_name

# https://docs.microsoft.com/en-us/azure/azure-monitor/learn/quick-create-workspace-cli
az group deployment create --resource-group $rg_name --name $analytics_workspace_name --template-file deploylaworkspacetemplate.json


##############################################################################################################################
#
# Create Azure Container Registry
#
##############################################################################################################################

az acr create --resource-group $rg_name --name $acr_registry_name --sku Premium --location $location

# Get the ACR registry resource id
acr_registry_id=$(az acr show --name $acr_registry_name --resource-group $rg_name --query "id" --output tsv)
echo "ACR registry ID :" $acr_registry_id
az acr repository list  --name $acr_registry_name --resource-group $rg_name

# Configure https://docs.microsoft.com/en-us/azure/container-registry/container-registry-geo-replication#configure-geo-replication
# https://docs.microsoft.com/en-us/cli/azure/acr/replication?view=azure-cli-latest
# location from az account list-locations : francecentral | northeurope | westeurope 
az acr replication create --location westeurope --registry $acr_registry_name --resource-group $rg_name
						  
# Create role assignment
az role assignment create --assignee $sp_id --role acrpull --scope $acr_registry_id

docker_server="$(az acr show --name $acr_registry_name --resource-group $rg_name --query "name" --output tsv)"".azurecr.io"
echo "Docker server :" $docker_server

kubectl create secret docker-registry acr-auth \
        --docker-server="$docker_server" \
        --docker-username="$sp_id" \
        --docker-email="youremail@groland.grd" \
        --docker-password="$sp_password"

kubectl get secrets


##############################################################################################################################
#
# Create Docker Image
#
##############################################################################################################################

# https://docs.microsoft.com/en-us/azure/container-registry/container-registry-tasks-pack-build#example-build-java-image-with-heroku-builder
# https://docs.microsoft.com/en-us/azure/container-registry/container-registry-quickstart-task-cli
git clone $git_url
cd spring-petclinic
mvn package

# Test the App
mvn spring-boot:run

# https://docs.microsoft.com/en-us/java/azure/jdk/java-jdk-docker-images?view=azure-java-stable
# https://github.com/microsoft/java/blob/master/docker/alpine/Dockerfile.zulu-8u222-jre
# https://itnext.io/migrating-a-spring-boot-service-to-kubernetes-in-5-steps-7c1702da81b6
# https://blog.nebrass.fr/playing-with-spring-boot-on-kubernetes/
# https://www.baeldung.com/spring-boot-minikube
# https://javaetmoi.com/2018/10/architecture-microservices-avec-spring-cloud/
# https://javaetmoi.com/2016/12/les-forks-de-spring-petclinic/

# Java 8 image : mcr.microsoft.com/java/jdk:8u222-zulu-alpine
# Java 11 image :  mcr.microsoft.com/java/jre:11u4-zulu-alpine
#artifact="spring-petclinic-2.1.0.BUILD-SNAPSHOT.jar"
artifact="spring-petclinic-2.1.0.BUILD-SNAPSHOT.jar"
echo -e "FROM mcr.microsoft.com/java/jre:11u4-zulu-alpine\n" \
"VOLUME /tmp \n" \
"ADD target/${artifact} app.jar \n" \
"RUN touch /app.jar \n" \
"EXPOSE 8080 \n" \
"ENTRYPOINT [ \""java\"", \""-Djava.security.egd=file:/dev/./urandom\"", \""-jar\"", \""/app.jar\"" ] \n"\
> Dockerfile

az acr build -t "${docker_server}/spring-petclinic:{{.Run.ID}}" -r  $acr_registry_name --file Dockerfile .
az acr repository list  --name $acr_registry_name --resource-group $rg_name

# Test container
# az acr run -r $acr_registry_name --cmd "${docker_server}/spring-petclinic:dd4" /dev/null
# https://docs.microsoft.com/en-us/azure/container-registry/container-registry-helm-repos

kubectl apply -f petclinic-deployment.yaml -n $target_namespace
kubectl get deployments -n $target_namespace
kubectl get deployment petclinic -n $target_namespace 
kubectl get pods -l app=petclinic -o wide -n $target_namespace
kubectl get pods -l app=petclinic -o yaml -n $target_namespace | grep podIP

# kubectl describe pod petclinic-649bdc4d5-964vl -n $target_namespace
# kubectl logs petclinic-649bdc4d5-964vl -n $target_namespace
# kubectl exec -ti POD-UID -- /bin/bash

##############################################################################################################################
#
# Expose service
#
##############################################################################################################################

kubectl apply -f petclinic-service-cluster-ip.yaml -n $target_namespace

# Standard load Balancer Use Case
# Use the command below to retrieve the External-IP of the Service. Make sure to allow a couple of minutes for the Azure Load Balancer to assign a public IP.
service_slb_ip=$(kubectl get service petclinic-service -n $target_namespace -o jsonpath="{.status.loadBalancer.ingress[*].ip}")
# All config proiperties ref: sur https://docs.spring.io/spring-boot/docs/current/reference/html/common-application-properties.html 
echo "Your service is now exposed through a Cluster IP at http://${service_slb_ip}"
echo "Check Live Probe with Spring Actuator : http://${service_slb_ip}/manage/health"
curl "http://${service_slb_ip}/manage/health" -i -X GET
echo "\n"
# You should received an UP reply :
# {
#  "status" : "UP"
# }
echo "Checkc spring Management Info at http://${service_slb_ip}/manage/info" -i -X GET
curl "http://${service_slb_ip}/manage/info" -i -X GET

# ClusterIP Use Case
# kubectl apply -f petclinic-service-clusterIP.yaml
helm repo update
kubectl apply -f helm-rbac.yaml
helm init --service-account tiller

helm upgrade --install ingress stable/nginx-ingress --namespace ingress
kubectl get svc -n ingress ingress-nginx-ingress-controller -o jsonpath="{.status.loadBalancer.ingress[*].ip}"



##############################################################################################################################
#
# Create App Gateway : 
# https://docs.microsoft.com/en-us/azure/application-gateway/ingress-controller-overview
# https://docs.microsoft.com/en-us/azure/aks/operator-best-practices-network#secure-traffic-with-a-web-application-firewall-waf 

# https://github.com/Azure/aks-bestpractices-ignite19
# 
# 
##############################################################################################################################

# https://docs.microsoft.com/en-us/azure/application-gateway/ingress-controller-install-new#create-an-identity
az ad sp create-for-rbac --skip-assignment -o json > auth.json
appId=$(jq -r ".appId" auth.json)
password=$(jq -r ".password" auth.json)

objectId=$(az ad sp show --id $appId --query "objectId" -o tsv)

cat <<EOF > parameters.json
{
  "aksServicePrincipalAppId": { "value": "$appId" },
  "aksServicePrincipalClientSecret": { "value": "$password" },
  "aksServicePrincipalObjectId": { "value": "$objectId" },
  "aksEnableRBAC": { "value": false }
}
EOF

wget https://raw.githubusercontent.com/Azure/application-gateway-kubernetes-ingress/master/deploy/azuredeploy.json -O template.json


# modify the template as needed
az group deployment create \
        -g $rg_name \
        -n $appgwName \
        --template-file template.json \
        --parameters parameters.json

az group deployment show -g $rg_name -n $appgwName --query "properties.outputs" -o json > deployment-outputs.json

kubectl apply -f agic.yaml
kubectl get ingresses --all-namespaces
kubectl get ingress 

##############################################################################################################################
#
# Create Key Vault
# 
##############################################################################################################################

# https://docs.microsoft.com/en-us/cli/azure/keyvault/secret?view=azure-cli-latest#az-keyvault-secret-set
az keyvault create --location $location --name $vault_name --resource-group $rg_name
az keyvault secret set --name  "${appName}-Secret" --vault-name $vault_name --description "${appName}-Secret" --value $vault_secret 
az keyvault secret list --vault-name $vault_name
az keyvault secret show --vault-name $vault_name --name "${appName}-Secret"  --output tsv

##############################################################################################################################
#
# Configure DNS
# https://github.com/kubernetes-incubator/external-dns/blob/master/docs/tutorials/azure.md
# https://docs.microsoft.com/en-us/azure/aks/http-application-routing
# 
# https://docs.microsoft.com/en-us/azure/dns/private-dns-scenarios#scenario-split-horizon-functionality
#
# https://azure.microsoft.com/en-us/resources/videos/custom-dns-records-with-azure-web-sites/
#
# https://docs.microsoft.com/en-us/azure/dns/dns-domain-delegation
# https://docs.microsoft.com/en-us/azure/dns/dns-delegate-domain-azure-dns 
# https://docs.microsoft.com/en-us/azure/networking/disaster-recovery-dns-traffic-manager#planning-your-disaster-recovery-architecture
# 
##############################################################################################################################

#"lighthouseparis2019.azurewebsites.net" 
#dnz_zone="azurewebsites.net" 
az network dns zone create -g $rg_name -n $dnz_zone
az network dns zone list -g $rg_name
az network dns record-set a add-record -g $rg_name -z $dnz_zone -n www -a ${service_slb_ip}
# az network dns record-set a add-record -g $rg_name -z $dnz_zone -n lighthouseparis -a ${service_slb_ip}
#az network dns record-set cname create -g $rg_name -z $dnz_zone -n lighthouseparis
#az network dns record-set cname set-record -g $rg_name -z $dnz_zone -n lighthouseparis -c lighthouseparis.$dnz_zone

az network dns record-set cname create -g lhparis-rg -z $dnz_zone -n sandbox
az network dns record-set cname set-record -g lhparis-rg -z $dnz_zone -n sandbox -c www.$dnz_zone

# az network dns record-set cname show -g $rg_name -z $rg_name -n test

az network dns record-set list -g $rg_name -z $dnz_zone


# To test DNS name resolution:
az network dns record-set ns show --resource-group $rg_name --zone-name $dnz_zone --name @

# https://docs.microsoft.com/en-us/azure/dns/dns-delegate-domain-azure-dns#delegate-the-domain
# In the registrar's DNS management page, edit the NS records and replace the NS records with the Azure DNS name servers.

# /!\ On your windows station , flush DNS ... : ipconfig /flushdns
# Mac: sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder; say cache flushed
nslookup www.$dnz_zone ns1-09.azure-dns.com

# https://aka.ms/lighthouse/blue mapped to http://lighthouseparis.akshandsonlabs.com
# https://aka.ms/lighthouse/green to be mapped to the SLB Public IP of DRP region


tenant_id=$(az account show --query "tenantId")
# sp_password=`cat spp.txt`
# touch /etc/kubernetes/azure.json
touch azure.json
echo -e "{
  \"tenantId\": \"${tenant_id}\",
  \"subscriptionId\": \"${subId}\",
  \"resourceGroup\": \"${rg_name}\",
  \"aadClientId\": \"${sp_id}\",
  \"aadClientSecret\": \"${sp_password}\"
}" > azure.json

kubectl create secret generic "${appName}-dns-secret" --from-file=azure.json
kubectl get secrets

rg_id=$(az group show --name ${rg_name} --query id --output tsv)
dns_zone_id=$(az network dns zone show --name ${dnz_zone} -g ${rg_name} --query id --output tsv)
az role assignment create --role "Reader" --assignee ${sp_id} --scope ${rg_id} 
az role assignment create --role "Contributor" --assignee ${sp_id} --scope ${dns_zone_id} 

##############################################################################################################################
#
# Enforce TLS with Ingress : https://docs.microsoft.com/en-us/azure/aks/ingress-tls
# https://github.com/helm/charts/blob/master/stable/nginx-ingress/README.md
# 
##############################################################################################################################



##############################################################################################################################
#
# Configure Spring to use PaaS Azure Database
# https://stackoverflow.com/questions/20274758/switching-databases-in-spring-petclinic
# https://github.com/spring-petclinic/spring-petclinic-rest/blob/master/readme.md 
# https://docs.microsoft.com/en-us/azure/mysql/quickstart-create-mysql-server-database-using-azure-cli 
# 
##############################################################################################################################

# spring.datasource.data-username= # Username of the database to execute DML scripts (if different).
# spring.datasource.data-password= # Password of the database to execute DML scripts (if different).
# spring.datasource.driver-class-name= # Fully qualified name of the JDBC driver. Auto-detected based on the URL by default.
# spring.datasource.username= # Login username of the database.
# spring.datasource.name= # Name of the datasource. Default to "testdb" when using an embedded database.
# spring.datasource.password= # Login password of the database.
# spring.datasource.schema= # Schema (DDL) script resource references.
# spring.datasource.type= # Fully qualified name of the connection pool implementation to use. By default, it is auto-detected from the classpath.
# spring.datasource.url= # JDBC URL of the database.
# spring.datasource.data= # Data (DML) script resource references.

##############################################################################################################################
#
# Configure secrets
# https://docs.microsoft.com/en-us/azure/aks/developer-best-practices-pod-security#use-pod-managed-identities
# 
##############################################################################################################################

##############################################################################################################################
#
# Configure Spring to enable TLS
# 
# 
##############################################################################################################################

# Generate a CSR
# https://docs.oracle.com/javase/8/docs/technotes/tools/unix/keytool.html#keytool_option_genkeypair		                                         #
# https://docs.oracle.com/en/java/javase/11/tools/keytool.html  


# https://docs.spring.io/spring-boot/docs/current/reference/html/howto-embedded-web-servers.html#howto-configure-ssl
# https://docs.spring.io/spring-boot/docs/current/reference/html/common-application-properties.html 



# https://howtodoinjava.com/spring-boot/spring-boot-ssl-https-example
# https://stackoverflow.com/questions/27989034/how-do-you-enable-tls-1-2-on-spring-boot
# https://github.com/ezYakaEagle442/spring-petclinic/tree/master/Certificates-Tools

# server.port=8443
# server.ssl.enabled=true
# server.ssl.enabled-protocols= TLSv1.2
# server.ssl.protocol=TLS

#server.ssl.key-alias=oss-java-web-app
#server.ssl.key-password=petclinic
#server.ssl.key-store=./oss-java-web-app.jks
#server.ssl.key-store-provider=SUN
#server.ssl.key-store-type=JKS

#server.ssl.trust-store=./oss-java-web-app.jks
#server.ssl.trust-store-password=changeit
#server.ssl.trust-store-provider=SUN
#server.ssl.trust-store-type=JKS


##############################################################################################################################
#
# Buy a custom domain with Azure: https://docs.microsoft.com/en-us/azure/app-service/manage-custom-dns-buy-domain
# 
# App Service Domains use GoDaddy for domain registration and Azure DNS to host the domains. 
# In addition to the domain registration fee, usage charges for Azure DNS apply. For information, see Azure DNS Pricing.
# The following top-level domains are supported by App Service domains: com, net, co.uk, org, nl, in, biz, org.uk, and co.in.
#
##############################################################################################################################
 
# Prerequisites: Create an App Service app
# To use custom domains in Azure App Service, your app's App Service plan must be a paid tier (Shared, Basic, Standard, or Premium). 
# https://docs.microsoft.com/en-us/cli/azure/appservice/plan?view=azure-cli-latest#az-appservice-plan-create
# The pricing tiers, e.g., F1(Free), D1(Shared), B1(Basic Small), B2(Basic Medium), B3(Basic Large), S1(Standard Small), P1V2(Premium V2 Small), PC2 (Premium Container Small), PC3 (Premium Container Medium), PC4 (Premium Container Large).

az appservice plan create -g ${rg_name} -n "gbbPlan" --number-of-workers 1 --sku B1 --subscription $subId
az appservice plan show --name "gbbPlan" --resource-group ${rg_name}
# $custom-dns

##############################################################################################################################
#
# Add Appplication Gateway.
# https://docs.microsoft.com/en-us/azure/application-gateway/create-ssl-portal
# https://docs.microsoft.com/en-us/azure/cloud-services/cloud-services-certs-create --> outdated !
# https://docs.microsoft.com/en-us/azure/application-gateway/certificates-for-backend-authentication
# 
##############################################################################################################################



##############################################################################################################################
#
# Manage certificates with KeyVault : 
# https://docs.microsoft.com/en-us/azure/key-vault/about-keys-secrets-and-certificates#key-vault-certificates 
# https://docs.microsoft.com/en-us/cli/azure/keyvault/certificate/issuer?view=azure-cli-latest
#
##############################################################################################################################





##############################################################################################################################
#
# Ops Monitoring
#
##############################################################################################################################
# https://docs.microsoft.com/en-us/azure/aks/developer-best-practices-resource-management#regularly-check-for-application-issues-with-kube-advisor
kubectl run --rm -i -t kube-advisor --image=mcr.microsoft.com/aks/kubeadvisor --restart=Never

kubectl run --rm -i -t kube-advisor --image=mcr.microsoft.com/aks/kubeadvisor --restart=Never --overrides="{ \"apiVersion\": \"v1\", \"spec\": { \"serviceAccountName\": \"kube-advisor\" } }"


##############################################################################################################################
#
# Clean-Up
#
##############################################################################################################################

az aks delete --name $cluster_name --resource-group $rg_name
az acr delete --resource-group $rg_name --name $acr_registry_name
az keyvault delete --location $location --name $vault_name --resource-group $rg_name
az network vnet delete --name $vnet_name --resource-group $rg_name --location $location
az network vnet subnet delete --name $subnet_name --vnet-name $vnet_name --resource-group $rg_name 
az network route-table route delete -g  $rg_name --route-table-name $route_table -n $route
az network route-table delete -g  $rg_name -n $route_table
az network dns record-set a delete -g $rg_name -z $dnz_zone -n www 
az network dns zone delete -g $rg_name -n $dnz_zone
az network dns zone list -g $rg_name
# /!\ IMPORTANT : Decide to keep or delete your service principal
# az ad sp delete --id $sp_id