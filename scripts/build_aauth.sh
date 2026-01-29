#!/bin/bash
# Build script for AAuth implementation
# Builds the required modules for AAuth development and testing
#
# Resilient build: tries full AAuth module build first, falls back to server-only
# build if that fails (e.g. due to model/infinispan test marshallers, testsuite
# issues, or proto-schema-compatibility network problems).
#
# Usage: ./scripts/build_aauth.sh

# Don't use set -e - we need to catch build failures and try fallback
set +e

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

# Primary build: AAuth modules + server
echo -e "${YELLOW}Attempt 1: Building AAuth modules + server${NC}"
echo -e "  - model/infinispan, services, quarkus/server, quarkus/deployment, quarkus/dist"
echo -e "${BLUE}./mvnw -pl model/infinispan,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true${NC}\n"

./mvnw -pl model/infinispan,services,quarkus/server,quarkus/deployment,quarkus/dist -am clean install -DskipTests -DskipProtoLock=true
BUILD_RESULT=$?

if [ $BUILD_RESULT -eq 0 ]; then
    echo -e "\n${GREEN}✓ Build completed successfully (primary)${NC}"
    echo -e "\n${GREEN}You can now run Keycloak with:${NC}"
    echo -e "  ${BLUE}java -jar quarkus/server/target/lib/quarkus-run.jar start-dev${NC}"
    exit 0
fi

# Fallback: server-only build (avoids model/infinispan tests, testsuite, etc.)
echo -e "\n${YELLOW}Primary build failed. Trying fallback: server-only build${NC}"
echo -e "  (Skips testsuite and other modules that may fail in dev environments)"
echo -e "${BLUE}./mvnw -pl quarkus/deployment,quarkus/dist -am -DskipTests -DskipProtoLock=true clean install${NC}\n"

./mvnw -pl quarkus/deployment,quarkus/dist -am -DskipTests -DskipProtoLock=true clean install
BUILD_RESULT=$?

if [ $BUILD_RESULT -eq 0 ]; then
    echo -e "\n${GREEN}✓ Build completed successfully (fallback - server only)${NC}"
    echo -e "\n${GREEN}You can now run Keycloak with:${NC}"
    echo -e "  ${BLUE}java -jar quarkus/server/target/lib/quarkus-run.jar start-dev${NC}"
    exit 0
fi

echo -e "\n${RED}✗ Build failed (both primary and fallback)${NC}"
echo -e "\n${YELLOW}Common causes:${NC}"
echo -e "  - JDK 17 or 21 required (check: java -version)"
echo -e "  - Network/proxy issues (try: -DskipProtoLock=true is already set)"
echo -e "  - Run full build: ./mvnw clean install"
exit 1
