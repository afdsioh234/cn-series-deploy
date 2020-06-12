############################################################################################
# Copyright 2020 Palo Alto Networks.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############################################################################################


# provider "kubernetes" {
#   config_path = local_file.kubeconfig.filename
# }

resource "local_file" "kubeconfig" {
  content  = local.kubeconfig
  filename = "${path.module}/${var.project}-kubeconfig"
}

resource "local_file" "auth_configmap" {
  content  = local.config_map_aws_auth
  filename = "${path.module}/${var.project}-auth-configmap.yaml"
}

resource "null_resource" "apply_configmap" {
  provisioner "local-exec" {
    command = "kubectl apply -f ${local_file.auth_configmap.filename} --kubeconfig ${local_file.kubeconfig.filename}"
  }
}

# resource "kubernetes_config_map" "aws_auth" {
#   metadata {
#     name      = "my-aws-auth"
#     namespace = "kube-system"
#   }

#   data = {
#     mapRoles = "${local.map_roles}"
#   }
# }