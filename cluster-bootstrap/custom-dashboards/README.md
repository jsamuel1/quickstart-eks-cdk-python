# Custom Grafana Dashboards

This directory contains custom Grafana dashboards for enhanced metrics visualization in the EKS cluster.

## Included Dashboards

1. **Kubernetes Cluster Monitoring**
   - Provides comprehensive views of CPU usage by namespace
   - Memory usage by namespace
   - Network traffic by pod
   - Pod status monitoring
   - Real-time metric visualization with customizable time ranges

## How it Works

1. The dashboards are stored as JSON files in this directory
2. During cluster deployment, the files are uploaded as ConfigMaps to the Kubernetes cluster
3. A Kubernetes Job is created to:
   - Import the dashboards into Grafana
   - Configure appropriate folders and permissions
   - Set up the visualization with proper data sources

## Adding Custom Dashboards

To add a new custom dashboard:

1. Create a new JSON file in this directory following Grafana dashboard export format
2. Update the eks_cluster.py file to include the new dashboard in the ConfigMap
3. Redeploy the cluster with `cdk deploy`

The dashboard configuration script (`configure-dashboards.py`) will automatically detect and import any JSON files in this directory.