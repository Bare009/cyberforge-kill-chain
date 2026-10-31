# Web UI

Planned: a trimmed copy of the AI-SOC React dashboard (React 19, Vite,
Tailwind, react-force-graph-2d) with login removed, showing:

- the incident list, worst risk first, with the merged-alert count;
- one incident: timeline, host/user path graph, reach-next, report;
- the ATT&CK matrix of detections.

It talks only to `killchain/api`.
