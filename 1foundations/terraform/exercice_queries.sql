-- Detect Source IPs Scanning ≥10 Ports
SELECT
  jsonPayload.connection.src_ip AS attacker_ip,
  COUNT(DISTINCT jsonPayload.connection.dest_port) AS unique_ports_targeted,
  ARRAY_AGG(DISTINCT CAST(jsonPayload.connection.dest_port AS INT64)) AS ports_list
FROM
  `bounc-473410.vpc_flow_and_audit_logs.compute_googleapis_com_vpc_flows_20251206`
WHERE
  resource.type = "gce_subnetwork"
  AND jsonPayload.connection.dest_port IS NOT NULL
GROUP BY
  attacker_ip
HAVING
  unique_ports_targeted >= 10
ORDER BY
  unique_ports_targeted DESC;

