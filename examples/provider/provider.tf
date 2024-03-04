terraform {
  required_providers {
    sops = {
      source  = "sunziping2016/sops"
      version = "~> 0.1"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.5"
    }
  }
}

data "sops_decrypt" "basic" {
  source           = "./basic.yaml"
  encrypted_format = "yaml"
  decrypted_format = "json"
}

resource "sops_encrypt" "basic" {
  unencrypted_content = data.sops_decrypt.basic.decrypted_content
  format              = "yaml"
}
