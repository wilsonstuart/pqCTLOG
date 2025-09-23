# Post-Quantum Certificate Compliance Dashboard

This dashboard provides visualization of certificate compliance with Post-Quantum cryptographic standards in OpenSearch Dashboards.

## Prerequisites

- Running OpenSearch and OpenSearch Dashboards
- Python 3.7+
- Required Python packages:
  ```
  pip install python-dotenv requests
  ```

## Setup

1. Copy the environment file and update with your OpenSearch credentials:
   ```bash
   cp .env.dashboard .env
   ```
   Edit the `.env` file with your OpenSearch and Dashboards configuration.

2. Run the setup script to create the dashboard:
   ```bash
   python scripts/setup_dashboard.py
   ```

## Accessing the Dashboard

1. Open your web browser and navigate to your OpenSearch Dashboards URL (default: http://localhost:5601)
2. Go to "Dashboards" in the left sidebar
3. Open the "Post-Quantum Certificate Compliance" dashboard

## Dashboard Features

- **Compliance Overview**: Pie chart showing the distribution of compliance levels
- **Algorithms Distribution**: Bar chart of signature algorithms in use
- **Key Sizes**: Box plot of key sizes by algorithm
- **Expiration Status**: Pie chart showing certificate expiration status
- **Compliance by Algorithm**: Stacked bar chart showing compliance levels by algorithm

## Customizing the Dashboard

You can modify the visualizations in OpenSearch Dashboards by:

1. Clicking "Edit" on any visualization
2. Using the visualization builder to modify the query or display options
3. Clicking "Save" to update the visualization

## Troubleshooting

- If you get authentication errors, verify your OpenSearch credentials in the `.env` file
- If the dashboard is empty, ensure you have certificate data in your OpenSearch index
- Check the OpenSearch logs for any errors during setup
