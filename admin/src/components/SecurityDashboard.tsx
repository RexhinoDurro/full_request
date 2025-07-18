// admin/src/components/SecurityDashboard.tsx
import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  AlertTriangle, 
  Eye, 
  Ban, 
  Activity,
  TrendingUp,
  Users,
  Lock,
  Zap,
  MapPin,
  Clock,
  AlertCircle,
  CheckCircle,
  XCircle,
  RefreshCw
} from 'lucide-react';
import { adminApiClient } from '../utils/api';

interface SecurityEvent {
  id: number;
  event_type: string;
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  ip_address: string;
  user_agent: string;
  description: string;
  timestamp: string;
  resolved: boolean;
  user?: {
    username: string;
  };
}

interface SecurityStats {
  events_24h: number;
  events_7d: number;
  critical_events_24h: number;
  high_events_24h: number;
  top_threats: Array<{ event_type: string; count: number }>;
  top_ips: Array<{ ip_address: string; count: number }>;
  threat_trends: Array<{
    date: string;
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  }>;
}

const SecurityDashboard: React.FC = () => {
  const [stats, setStats] = useState<SecurityStats | null>(null);
  const [recentEvents, setRecentEvents] = useState<SecurityEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    loadSecurityData();
    
    // Auto-refresh every 30 seconds
    const interval = setInterval(loadSecurityData, 30000);
    return () => clearInterval(interval);
  }, []);

  const loadSecurityData = async () => {
    try {
      setError('');
      const [statsResponse, eventsResponse] = await Promise.all([
        adminApiClient.getSecurityStats(),
        adminApiClient.getSecurityEvents({ limit: 10 })
      ]);
      
      setStats(statsResponse.data);
      setRecentEvents(eventsResponse.data?.results || []);
    } catch (err) {
      setError('Failed to load security data');
      console.error('Security data error:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  };

  const handleRefresh = () => {
    setRefreshing(true);
    loadSecurityData();
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'CRITICAL': return 'text-red-600 bg-red-100';
      case 'HIGH': return 'text-orange-600 bg-orange-100';
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-100';
      case 'LOW': return 'text-blue-600 bg-blue-100';
      default: return 'text-gray-600 bg-gray-100';
    }
  };

  const getEventTypeIcon = (eventType: string) => {
    switch (eventType) {
      case 'LOGIN_ATTEMPT':
      case 'LOGIN_FAILURE': return <Lock className="w-4 h-4" />;
      case 'RATE_LIMIT': return <Zap className="w-4 h-4" />;
      case 'SQL_INJECTION':
      case 'XSS_ATTEMPT': return <AlertTriangle className="w-4 h-4" />;
      case 'ADMIN_ACCESS': return <Shield className="w-4 h-4" />;
      case 'SUSPICIOUS_IP': return <MapPin className="w-4 h-4" />;
      default: return <Eye className="w-4 h-4" />;
    }
  };

  const formatEventType = (eventType: string) => {
    return eventType.replace(/_/g, ' ').toLowerCase().replace(/\b\w/g, l => l.toUpperCase());
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <RefreshCw className="w-8 h-8 animate-spin text-blue-500 mx-auto mb-4" />
          <p className="text-gray-600">Loading security dashboard...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto p-6">
        {/* Header */}
        <div className="flex justify-between items-center mb-8">
          <div>
            <h1 className="text-3xl font-bold text-gray-900 flex items-center">
              <Shield className="w-8 h-8 text-blue-600 mr-3" />
              Security Monitoring
            </h1>
            <p className="text-gray-600 mt-2">Real-time security events and threat analysis</p>
          </div>
          
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center space-x-2 px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${refreshing ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center space-x-2">
            <AlertCircle className="w-5 h-5 text-red-500" />
            <span className="text-red-700">{error}</span>
          </div>
        )}

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-4 gap-6 mb-8">
            <div className="bg-white p-6 rounded-xl shadow-sm border">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-600 text-sm">Events (24h)</p>
                  <p className="text-3xl font-bold text-gray-900">{stats.events_24h}</p>
                </div>
                <Activity className="w-8 h-8 text-blue-500" />
              </div>
            </div>

            <div className="bg-white p-6 rounded-xl shadow-sm border">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-600 text-sm">Critical Events</p>
                  <p className="text-3xl font-bold text-red-600">{stats.critical_events_24h}</p>
                </div>
                <AlertTriangle className="w-8 h-8 text-red-500" />
              </div>
            </div>

            <div className="bg-white p-6 rounded-xl shadow-sm border">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-600 text-sm">High Priority</p>
                  <p className="text-3xl font-bold text-orange-600">{stats.high_events_24h}</p>
                </div>
                <Eye className="w-8 h-8 text-orange-500" />
              </div>
            </div>

            <div className="bg-white p-6 rounded-xl shadow-sm border">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-600 text-sm">Events (7d)</p>
                  <p className="text-3xl font-bold text-gray-900">{stats.events_7d}</p>
                </div>
                <TrendingUp className="w-8 h-8 text-green-500" />
              </div>
            </div>
          </div>
        )}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Security Events */}
          <div className="bg-white rounded-xl shadow-sm border">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                <AlertCircle className="w-5 h-5 text-red-500 mr-2" />
                Recent Security Events
              </h3>
            </div>
            
            <div className="divide-y divide-gray-200">
              {recentEvents.length > 0 ? (
                recentEvents.map((event) => (
                  <div key={event.id} className="p-4 hover:bg-gray-50">
                    <div className="flex items-start justify-between">
                      <div className="flex items-start space-x-3">
                        <div className={`p-2 rounded-lg ${getSeverityColor(event.severity)}`}>
                          {getEventTypeIcon(event.event_type)}
                        </div>
                        
                        <div className="flex-1">
                          <div className="flex items-center space-x-2">
                            <h4 className="font-medium text-gray-900">
                              {formatEventType(event.event_type)}
                            </h4>
                            <span className={`px-2 py-1 rounded-full text-xs font-medium ${getSeverityColor(event.severity)}`}>
                              {event.severity}
                            </span>
                          </div>
                          
                          <p className="text-sm text-gray-600 mt-1">{event.description}</p>
                          
                          <div className="flex items-center space-x-4 mt-2 text-xs text-gray-500">
                            <span className="flex items-center">
                              <MapPin className="w-3 h-3 mr-1" />
                              {event.ip_address}
                            </span>
                            <span className="flex items-center">
                              <Clock className="w-3 h-3 mr-1" />
                              {new Date(event.timestamp).toLocaleString()}
                            </span>
                            {event.user && (
                              <span className="flex items-center">
                                <Users className="w-3 h-3 mr-1" />
                                {event.user.username}
                              </span>
                            )}
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex items-center">
                        {event.resolved ? (
                          <CheckCircle className="w-5 h-5 text-green-500" />
                        ) : (
                          <XCircle className="w-5 h-5 text-red-500" />
                        )}
                      </div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="p-8 text-center text-gray-500">
                  <Shield className="w-12 h-12 mx-auto mb-4 text-gray-300" />
                  <p>No recent security events</p>
                </div>
              )}
            </div>
          </div>

          {/* Top Threats */}
          {stats && (
            <div className="bg-white rounded-xl shadow-sm border">
              <div className="p-6 border-b border-gray-200">
                <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                  <Ban className="w-5 h-5 text-orange-500 mr-2" />
                  Top Threat Types
                </h3>
              </div>
              
              <div className="p-6">
                <div className="space-y-4">
                  {stats.top_threats.length > 0 ? (
                    stats.top_threats.map((threat, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                        <div className="flex items-center space-x-3">
                          <div className="w-8 h-8 bg-red-100 rounded-full flex items-center justify-center">
                            <span className="text-red-600 font-bold text-sm">{index + 1}</span>
                          </div>
                          <span className="font-medium text-gray-900">
                            {formatEventType(threat.event_type)}
                          </span>
                        </div>
                        <span className="bg-red-100 text-red-800 px-3 py-1 rounded-full text-sm font-medium">
                          {threat.count}
                        </span>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500 text-center py-4">No threat data available</p>
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Threat Trends Chart */}
        {stats && stats.threat_trends.length > 0 && (
          <div className="mt-8 bg-white rounded-xl shadow-sm border">
            <div className="p-6 border-b border-gray-200">
              <h3 className="text-lg font-semibold text-gray-900 flex items-center">
                <TrendingUp className="w-5 h-5 text-blue-500 mr-2" />
                Security Trends (7 Days)
              </h3>
            </div>
            
            <div className="p-6">
              <div className="h-64 flex items-end space-x-2">
                {stats.threat_trends.map((day, index) => {
                  const maxHeight = Math.max(...stats.threat_trends.map(d => d.total));
                  const height = maxHeight > 0 ? (day.total / maxHeight) * 200 : 0;
                  
                  return (
                    <div key={index} className="flex-1 flex flex-col items-center">
                      <div className="w-full bg-gray-200 rounded-t relative" style={{ height: '200px' }}>
                        {/* Critical events */}
                        {day.critical > 0 && (
                          <div 
                            className="absolute bottom-0 w-full bg-red-500 rounded-t"
                            style={{ height: `${(day.critical / maxHeight) * 200}px` }}
                          />
                        )}
                        {/* High events */}
                        {day.high > 0 && (
                          <div 
                            className="absolute bottom-0 w-full bg-orange-500 rounded-t"
                            style={{ 
                              height: `${((day.critical + day.high) / maxHeight) * 200}px`,
                              bottom: `${(day.critical / maxHeight) * 200}px`
                            }}
                          />
                        )}
                        {/* Medium events */}
                        {day.medium > 0 && (
                          <div 
                            className="absolute bottom-0 w-full bg-yellow-500 rounded-t"
                            style={{ 
                              height: `${((day.critical + day.high + day.medium) / maxHeight) * 200}px`,
                              bottom: `${((day.critical + day.high) / maxHeight) * 200}px`
                            }}
                          />
                        )}
                      </div>
                      
                      <div className="text-xs text-gray-500 mt-2 text-center">
                        <div>{new Date(day.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</div>
                        <div className="font-medium">{day.total}</div>
                      </div>
                    </div>
                  );
                })}
              </div>
              
              {/* Legend */}
              <div className="flex justify-center space-x-6 mt-4">
                <div className="flex items-center space-x-2">
                  <div className="w-4 h-4 bg-red-500 rounded"></div>
                  <span className="text-sm text-gray-600">Critical</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-4 h-4 bg-orange-500 rounded"></div>
                  <span className="text-sm text-gray-600">High</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-4 h-4 bg-yellow-500 rounded"></div>
                  <span className="text-sm text-gray-600">Medium</span>
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-4 h-4 bg-blue-500 rounded"></div>
                  <span className="text-sm text-gray-600">Low</span>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default SecurityDashboard;