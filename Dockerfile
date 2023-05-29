ARG branch=latest
FROM cccs/assemblyline-v4-service-base:$branch

ENV SERVICE_PATH overpower.Overpower

USER root
# Update the list of packages
RUN apt-get update
# Install pre-requisite packages.
RUN apt-get install -y wget apt-transport-https software-properties-common
# Download the Microsoft repository GPG keys
RUN wget https://packages.microsoft.com/config/debian/10/packages-microsoft-prod.deb
# Register the Microsoft repository GPG keys
RUN dpkg -i packages-microsoft-prod.deb
# Update the list of packages after we added packages.microsoft.com
RUN apt-get update
# Install PowerShell
RUN apt-get install -y powershell
# Cleanup
RUN rm packages-microsoft-prod.deb

# Create the directory for the PSDecode module
RUN mkdir -p /home/assemblyline/.local/share/powershell/Modules/PSDecode
RUN mkdir -p /var/lib/assemblyline/.local/share/powershell/Modules/PSDecode
# Move the PSDecode module to the correct directory
COPY tools/PSDecode.psm1 /home/assemblyline/.local/share/powershell/Modules/PSDecode
COPY tools/PSDecode.psm1 /var/lib/assemblyline/.local/share/powershell/Modules/PSDecode

# Switch to assemblyline user
USER assemblyline

RUN echo "Testing pwsh if PSDecode exists"
RUN pwsh -Command printenv PSModulePath
RUN pwsh -Command Get-Module -ListAvailable -Name PSDecode

# Install python dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir --user --requirement requirements.txt && rm -rf ~/.cache/pip

# Copy Overpower service code
WORKDIR /opt/al_service
COPY . .

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Allow PSDecode to create directories
RUN chown -R assemblyline:assemblyline /opt/al_service

# Switch to assemblyline user
USER assemblyline
