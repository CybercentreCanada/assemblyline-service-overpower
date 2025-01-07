[![Discord](https://img.shields.io/badge/chat-on%20discord-7289da.svg?sanitize=true)](https://discord.gg/GUAy9wErNu)
[![](https://img.shields.io/discord/908084610158714900)](https://discord.gg/GUAy9wErNu)
[![Static Badge](https://img.shields.io/badge/github-assemblyline-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline)
[![Static Badge](https://img.shields.io/badge/github-assemblyline_service_overpower-blue?logo=github)](https://github.com/CybercentreCanada/assemblyline-service-overpower)
[![GitHub Issues or Pull Requests by label](https://img.shields.io/github/issues/CybercentreCanada/assemblyline/service-overpower)](https://github.com/CybercentreCanada/assemblyline/issues?q=is:issue+is:open+label:service-overpower)
[![License](https://img.shields.io/github/license/CybercentreCanada/assemblyline-service-overpower)](./LICENSE)

# Overpower Service

De-obfuscates PowerShell files, profiles them and runs them.

## Service Details

Uses _modified_ open-source tools to de-obfuscate and score PowerShell files, such as:

- [PSDecode](https://github.com/R3MRUM/PSDecode): PowerShell script for de-obfuscating encoded PowerShell scripts
- [PowerShellProfiler](https://github.com/pan-unit42/public_tools/tree/master/powershellprofiler): Palo Alto Networks Unit42 tool for statically analyzing PowerShell scripts by de-obfuscating and normalizing the content which is then profiled for behavioural indicators.
<!-- * [box-ps](https://github.com/ConnorShride/box-ps): Powershell sandboxing utility. -->

### Submission Parameters

- `tool_timeout`: The length of time we will allow tools to individually run for.
- `add_supplementary`: If you want supplementary files to be added to the result, select this.
  PSDecode parameters:
- `fake_web_download`: A flag that is used for indicating if a web request to download a file to disk should be faked.

## Image variants and tags

Assemblyline services are built from the [Assemblyline service base image](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
which is based on Debian 11 with Python 3.11.

Assemblyline services use the following tag definitions:

| **Tag Type** | **Description**                                                                                  |      **Example Tag**       |
| :----------: | :----------------------------------------------------------------------------------------------- | :------------------------: |
|    latest    | The most recent build (can be unstable).                                                         |          `latest`          |
|  build_type  | The type of build used. `dev` is the latest unstable build. `stable` is the latest stable build. |     `stable` or `dev`      |
|    series    | Complete build details, including version and build type: `version.buildType`.                   | `4.5.stable`, `4.5.1.dev3` |

## Running this service

This is an Assemblyline service. It is designed to run as part of the Assemblyline framework.

If you would like to test this service locally, you can run the Docker image directly from the a shell:

    docker run \
        --name Overpower \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-overpower

To add this service to your Assemblyline deployment, follow this
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

General Assemblyline documentation can be found at: https://cybercentrecanada.github.io/assemblyline4_docs/

# Service Overpower

Désobfusque les fichiers PowerShell, les profile et les exécute.

## Détails du service

Utilise des outils open-source _modifiés_ pour désobfusquer et noter les fichiers PowerShell, tels que :

- [PSDecode](https://github.com/R3MRUM/PSDecode) : Script PowerShell pour désobfusquer les scripts PowerShell encodés.
- PowerShellProfiler](https://github.com/pan-unit42/public_tools/tree/master/powershellprofiler) : Outil Unit42 de Palo Alto Networks pour l'analyse statique des scripts PowerShell en désobfusquant et en normalisant le contenu qui est ensuite profilé pour des indicateurs comportementaux.
<!-- * [box-ps](https://github.com/ConnorShride/box-ps) : Utilitaire de sandboxing Powershell. -->

### Paramètres de soumission

- `tool_timeout` : La durée pendant laquelle nous autoriserons les outils à s'exécuter individuellement.
- `add_supplementary` : Si vous souhaitez que des fichiers supplémentaires soient ajoutés au résultat, sélectionnez cette option.
  Paramètres PSDecode :
- `fake_web_download` : Un drapeau qui est utilisé pour indiquer si une requête web pour télécharger un fichier sur le disque doit être simulée.

## Variantes et étiquettes d'image

Les services d'Assemblyline sont construits à partir de l'image de base [Assemblyline service](https://hub.docker.com/r/cccs/assemblyline-v4-service-base),
qui est basée sur Debian 11 avec Python 3.11.

Les services d'Assemblyline utilisent les définitions d'étiquettes suivantes:

| **Type d'étiquette** | **Description**                                                                                                |  **Exemple d'étiquette**   |
| :------------------: | :------------------------------------------------------------------------------------------------------------- | :------------------------: |
|   dernière version   | La version la plus récente (peut être instable).                                                               |          `latest`          |
|      build_type      | Type de construction utilisé. `dev` est la dernière version instable. `stable` est la dernière version stable. |     `stable` ou `dev`      |
|        série         | Détails de construction complets, comprenant la version et le type de build: `version.buildType`.              | `4.5.stable`, `4.5.1.dev3` |

## Exécution de ce service

Ce service est spécialement optimisé pour fonctionner dans le cadre d'un déploiement d'Assemblyline.

Si vous souhaitez tester ce service localement, vous pouvez exécuter l'image Docker directement à partir d'un terminal:

    docker run \
        --name Overpower \
        --env SERVICE_API_HOST=http://`ip addr show docker0 | grep "inet " | awk '{print $2}' | cut -f1 -d"/"`:5003 \
        --network=host \
        cccs/assemblyline-service-overpower

Pour ajouter ce service à votre déploiement d'Assemblyline, suivez ceci
[guide](https://cybercentrecanada.github.io/assemblyline4_docs/fr/developer_manual/services/run_your_service/#add-the-container-to-your-deployment).

## Documentation

La documentation générale sur Assemblyline peut être consultée à l'adresse suivante: https://cybercentrecanada.github.io/assemblyline4_docs/
