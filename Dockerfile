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

# Switch to assemblyline user
USER assemblyline

# Install pip packages
RUN pip install --no-cache-dir --user tld && rm -rf ~/.cache/pip

# Copy Overpower service code
WORKDIR /opt/al_service
COPY . .

RUN mkdir -p /var/lib/assemblyline/.local/share/powershell/Modules/PSDecode
COPY tools/PSDecode.psm1 /var/lib/assemblyline/.local/share/powershell/Modules/PSDecode

# Patch version in manifest
ARG version=4.0.0.dev1
USER root
RUN sed -i -e "s/\$SERVICE_TAG/$version/g" service_manifest.yml

# Switch to assemblyline user
USER assemblyline
