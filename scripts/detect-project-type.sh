#!/bin/bash

# Project Type Detection Script for Agent OS
# Automatically detects project type based on codebase structure and files

set -e

PROJECT_DIR="${1:-.}"

# Function to check if file exists
file_exists() {
    [ -f "$PROJECT_DIR/$1" ]
}

# Function to check if directory exists
dir_exists() {
    [ -d "$PROJECT_DIR/$1" ]
}

# Function to detect backend API projects
detect_backend_api() {
    # Check for Spring Boot
    if file_exists "pom.xml" && grep -q "spring-boot" "$PROJECT_DIR/pom.xml" 2>/dev/null; then
        return 0
    fi
    
    # Check for Gradle with Spring
    if file_exists "build.gradle" && grep -q "spring" "$PROJECT_DIR/build.gradle" 2>/dev/null; then
        return 0
    fi
    
    # Check for typical backend directory structure
    if dir_exists "src/main/java" && dir_exists "src/main/resources"; then
        return 0
    fi
    
    # Check for API-related files
    if file_exists "application.properties" || file_exists "application.yml"; then
        return 0
    fi
    
    return 1
}

# Function to detect dashboard/UI projects
detect_dashboard_ui() {
    # Check for package.json (Node.js project)
    if file_exists "package.json"; then
        local package_json="$PROJECT_DIR/package.json"
        
        # Check for React
        if grep -q "\"react\"" "$package_json" 2>/dev/null; then
            return 0
        fi
        
        # Check for Vue
        if grep -q "\"vue\"" "$package_json" 2>/dev/null; then
            return 0
        fi
        
        # Check for Angular
        if grep -q "\"@angular/core\"" "$package_json" 2>/dev/null; then
            return 0
        fi
        
        # Check for Next.js
        if grep -q "\"next\"" "$package_json" 2>/dev/null; then
            return 0
        fi
    fi
    
    # Check for typical frontend directories
    if dir_exists "src/components" || dir_exists "src/pages" || dir_exists "public"; then
        return 0
    fi
    
    # Check for HTML/CSS/JS files in root or src
    if file_exists "index.html" || file_exists "src/index.html"; then
        return 0
    fi
    
    return 1
}

# Function to detect data pipeline projects
detect_data_pipeline() {
    # Check for Python data processing frameworks
    if file_exists "requirements.txt"; then
        local requirements="$PROJECT_DIR/requirements.txt"
        
        # Check for common data processing libraries
        if grep -qE "(pandas|numpy|apache-beam|airflow|luigi|prefect|dagster)" "$requirements" 2>/dev/null; then
            return 0
        fi
    fi
    
    # Check for Pipfile (pipenv)
    if file_exists "Pipfile" && grep -qE "(pandas|airflow|beam)" "$PROJECT_DIR/Pipfile" 2>/dev/null; then
        return 0
    fi
    
    # Check for common pipeline directories
    if dir_exists "dags" || dir_exists "pipelines" || dir_exists "etl"; then
        return 0
    fi
    
    # Check for pipeline configuration files
    if file_exists "airflow.cfg" || file_exists "pipeline.yaml" || file_exists "dag.yaml"; then
        return 0
    fi
    
    # Check for data retrieval/processing keywords in project name
    local project_name=$(basename "$PROJECT_DIR")
    if [[ "$project_name" =~ (pipeline|etl|data|retrieval|processing) ]]; then
        return 0
    fi
    
    return 1
}

# Function to detect infrastructure projects
detect_infrastructure() {
    # Check for Terraform
    if file_exists "main.tf" || file_exists "variables.tf" || dir_exists "terraform"; then
        return 0
    fi
    
    # Check for Kubernetes
    if dir_exists "k8s" || dir_exists "kubernetes" || file_exists "kustomization.yaml"; then
        return 0
    fi
    
    # Check for Helm charts
    if file_exists "Chart.yaml" || dir_exists "charts"; then
        return 0
    fi
    
    # Check for Docker Compose
    if file_exists "docker-compose.yml" || file_exists "docker-compose.yaml"; then
        # If it's just docker-compose for development, not infrastructure
        if ! dir_exists "terraform" && ! dir_exists "k8s"; then
            return 1
        fi
        return 0
    fi
    
    # Check for Ansible
    if file_exists "ansible.cfg" || dir_exists "playbooks"; then
        return 0
    fi
    
    # Check for CloudFormation
    if dir_exists "cloudformation" || file_exists "template.yaml"; then
        return 0
    fi
    
    # Check for infrastructure keywords in project name
    local project_name=$(basename "$PROJECT_DIR")
    if [[ "$project_name" =~ (infrastructure|infra|terraform|k8s|kubernetes|fabric|topology|provisioning) ]]; then
        return 0
    fi
    
    return 1
}

# Main detection logic
detect_project_type() {
    # Priority order: Infrastructure → Backend API → Data Pipeline → Dashboard/UI
    
    if detect_infrastructure; then
        echo "infrastructure"
        return 0
    fi
    
    if detect_backend_api; then
        echo "backend-api"
        return 0
    fi
    
    if detect_data_pipeline; then
        echo "data-pipeline"
        return 0
    fi
    
    if detect_dashboard_ui; then
        echo "dashboard-ui"
        return 0
    fi
    
    # Default to backend-api if can't determine
    echo "backend-api"
    return 0
}

# Main execution
main() {
    if [ ! -d "$PROJECT_DIR" ]; then
        echo "Error: Directory $PROJECT_DIR does not exist" >&2
        exit 1
    fi
    
    PROJECT_TYPE=$(detect_project_type)
    echo "$PROJECT_TYPE"
    
    # Optional: Log detection details if DEBUG is set
    if [ -n "$DEBUG" ]; then
        echo "Detected project type: $PROJECT_TYPE" >&2
        echo "Project directory: $PROJECT_DIR" >&2
    fi
}

# Run main function
main

