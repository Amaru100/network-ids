import React, { useState, useEffect } from 'react';
import { supabase } from '../lib/supabase';
import { Monitor } from 'lucide-react';

const HEARTBEAT_TIMEOUT_MS = 60000; // 60 seconds

function AgentStatus() {
  const [agents, setAgents] = useState([]);

  const fetchAgents = async () => {
    const { data } = await supabase
      .from('agents')
      .select('*')
      .order('last_heartbeat', { ascending: false });

    if (data) {
      const now = Date.now();
      const withStatus = data.map((agent) => ({
        ...agent,
        status:
          now - new Date(agent.last_heartbeat).getTime() < HEARTBEAT_TIMEOUT_MS
            ? 'online'
            : 'offline',
      }));
      setAgents(withStatus);
    }
  };

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 10000);
    return () => clearInterval(interval);
  }, []);

  const onlineCount = agents.filter((a) => a.status === 'online').length;

  return (
    <div className="card agent-status-card">
      <div className="card-header">
        <h2>
          <Monitor size={18} style={{ marginRight: 8, verticalAlign: 'middle' }} />
          Monitored Agents
        </h2>
        <span className="agent-summary">
          {onlineCount}/{agents.length} online
        </span>
      </div>

      {agents.length === 0 ? (
        <div className="empty-state">
          <p>No agents registered yet.</p>
          <p className="empty-hint">
            Run the capture agent on a machine to register it.
          </p>
        </div>
      ) : (
        <div className="agent-list">
          {agents.map((agent) => (
            <div key={agent.id} className={`agent-item ${agent.status}`}>
              <div className="agent-status-dot" />
              <div className="agent-info">
                <span className="agent-name">{agent.agent_name}</span>
                <span className="agent-detail">
                  {agent.ip_address} &middot; {agent.os_info}
                </span>
              </div>
              <div className="agent-meta">
                <span className={`agent-badge ${agent.status}`}>
                  {agent.status}
                </span>
                <span className="agent-heartbeat">
                  {formatLastSeen(agent.last_heartbeat)}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

function formatLastSeen(timestamp) {
  if (!timestamp) return 'Never';
  const diff = Date.now() - new Date(timestamp).getTime();
  if (diff < 60000) return 'Just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

export default AgentStatus;
