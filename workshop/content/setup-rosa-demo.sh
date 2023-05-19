#!/bin/bash
set -e

# Assuming ROSA CLI, OC CLI, AWS CLI, are already installed. Also that OC is already logged in with the cluster-admin
# This script sets up the project to enable the ostoy app to connect with s3.

wget -q -P ${HOME} https://raw.githubusercontent.com/openshift-cs/rosaworkshop/master/rosa-workshop/ostoy/yaml/ostoy-microservice-deployment.yaml
curl -s https://raw.githubusercontent.com/openshift-cs/rosaworkshop/master/rosa-workshop/ostoy/yaml/ostoy-frontend-deployment.yaml | sed 's/\# serviceAccount/serviceAccount/' > ${HOME}/ostoy-frontend-deployment.yaml

AWS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
OSTOY_NAMESPACE=$(oc config view --minify -o 'jsonpath={..namespace}')
POLICY_ARN=$(aws iam list-policies --query 'Policies[?PolicyName==`AmazonS3FullAccess`].Arn' --output text)
OIDC_PROVIDER=$(rosa describe cluster -c rosa-$GUID -o yaml | awk '/oidc_endpoint_url/ {print $2}' | cut -d '/' -f 3,4)

if [ -z "$OIDC_PROVIDER" ] && [ -z "$AWS_ACCOUNT_ID" ] && [ -z "$OSTOY_NAMESPACE" ] && [ -z "$POLICY_ARN" ]; then
    echo "All variables are null."
elif [ -z "$OIDC_PROVIDER" ]; then
    echo "OIDC_PROVIDER is null."
    exit 1
elif [ -z "$AWS_ACCOUNT_ID" ]; then
    echo "AWS_ACCOUNT_ID is null."
    exit 1
elif [ -z "$OSTOY_NAMESPACE" ]; then
    echo "OSTOY_NAMESPACE is null."
    exit 1
elif [ -z "$POLICY_ARN" ]; then
    echo "POLICY_ARN is null."
    exit 1
else
    echo "Varaibles are set...ok."
fi

oc new-project ostoy-$GUID

cat <<EOF > $HOME/ostoy-sa-trust.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${AWS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:${OSTOY_NAMESPACE}:ostoy-sa"
        }
      }
    }
  ]
}
EOF

aws iam create-role --role-name "ostoy-sa-role" --assume-role-policy-document file://${HOME}/ostoy-sa-trust.json
aws iam attach-role-policy --role-name "ostoy-sa-role" --policy-arn "${POLICY_ARN}"

APP_IAM_ROLE_ARN=$(aws iam get-role --role-name=ostoy-sa-role --query Role.Arn --output text)


cat <<EOF | oc apply -f -
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ostoy-sa
  namespace: ostoy-${GUID}
  annotations:
    eks.amazonaws.com/role-arn: "$APP_IAM_ROLE_ARN"
EOF
