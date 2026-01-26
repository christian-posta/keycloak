#!/bin/bash
# Build script for AAuth implementation
# Builds the required modules for AAuth development and testing
#
# Usage: ./scripts/build_aauth.sh

set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}=== Building AAuth Implementation ===${NC}\n"

# Check if Maven wrapper exists
if [ ! -f "./mvnw" ]; then
    echo -e "${RED}ERROR: Maven wrapper (./mvnw) not found${NC}"
    echo "Please run this script from the Keycloak root directory"
    exit 1
fi

# Make mvnw executable if it isn't already
chmod +x ./mvnw

echo -e "${YELLOW}Building modules:${NC}"
echo -e "  - model/infinispan"
echo -e "  - services"
echo -e "  - quarkus/server"
echo -e "  - quarkus/deployment"
echo -e "  - quarkus/dist"
echo ""

echo -e "${YELLOW}Maven command:${NC}"
echo -e "${BLUE}./mvnw -pl model/infinispan,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true${NC}\n"

# Run the build
./mvnw -pl model/infinispan,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true

BUILD_RESULT=$?

if [ $BUILD_RESULT -eq 0 ]; then
    echo -e "\n${GREEN}✓ Build completed successfully${NC}"
    echo -e "\n${GREEN}You can now run Keycloak with:${NC}"
    echo -e "  ${BLUE}java -jar quarkus/server/target/lib/quarkus-run.jar start-dev${NC}"
    exit 0
else
    echo -e "\n${RED}✗ Build failed${NC}"
    exit 1
fi
