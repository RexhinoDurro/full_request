import React, { useState, useEffect } from 'react';
import { 
  Users, 
  FileText, 
  Download, 
  Calendar, 
  TrendingUp,
  AlertCircle,
  Loader,
  Eye,
  Trash2,
  Filter,
  Search,
  BarChart3,
  X,
  AlertTriangle,
  CheckCircle
} from 'lucide-react';
import { adminApiClient, type Submission, type SubmissionStats, type SubmissionDetail, type FilterOptions, type SubmissionFilters } from '../utils/api';

// Safe defaults for all data
const DEFAULT_STATS: SubmissionStats = {
  total_submissions: 0,
  service_type_breakdown: {},
  country_breakdown: {},
  issue_timeframe_breakdown: {},
  daily_submissions: [],
  date_range: {
    from: '',
    to: '',
    preset: ''
  }
};

const DEFAULT_FILTER_OPTIONS: FilterOptions = {
  service_types: [],
  issue_timeframes: [],
  acknowledgments: [],
  primary_goals: [],
  heard_abouts: [],
  communication_methods: [],
  countries: []
};

const Dashboard: React.FC = () => {
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [stats, setStats] = useState<SubmissionStats | null>(null);
  const [filterOptions, setFilterOptions] = useState<FilterOptions | null>(null);
  const [selectedSubmission, setSelectedSubmission] = useState<SubmissionDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isDownloading, setIsDownloading] = useState(false);
  const [error, setError] = useState('');
  const [successMessage, setSuccessMessage] = useState('');
  const [activeTab, setActiveTab] = useState<'submissions' | 'analytics'>('submissions');
  
  // Filter states
  const [filters, setFilters] = useState<SubmissionFilters>({});
  const [showFilters, setShowFilters] = useState(false);
  
  // Delete states
  const [showDeleteAllModal, setShowDeleteAllModal] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState('');
  const [isDeleting, setIsDeleting] = useState(false);

  // Safe accessors for data
  const safeStats = stats || DEFAULT_STATS;
  const safeFilterOptions = filterOptions || DEFAULT_FILTER_OPTIONS;
  const safeSubmissions = Array.isArray(submissions) ? submissions : [];

  useEffect(() => {
    const initializeData = async () => {
      try {
        setIsLoading(true);
        setError('');
        
        await Promise.all([
          loadData(),
          loadFilterOptions()
        ]);
        
        // 🔧 FIXED: Load stats on initial load regardless of active tab
        await loadStats();
        
      } catch (error) {
        console.error('Failed to initialize dashboard:', error);
        setError('Failed to load dashboard data');
      } finally {
        setIsLoading(false);
      }
    };

    initializeData();
  }, []);

  useEffect(() => {
    // 🔧 FIXED: Load data when filters change, and always load stats
    if (Object.keys(filters).length > 0) {
      loadData();
      loadStats(); // Always load stats when filters change
    }
  }, [filters]);

  // Auto-clear messages after 5 seconds
  useEffect(() => {
    if (error || successMessage) {
      const timer = setTimeout(() => {
        setError('');
        setSuccessMessage('');
      }, 5000);
      return () => clearTimeout(timer);
    }
  }, [error, successMessage]);

  const loadData = async () => {
    try {
      const submissionsResponse = await adminApiClient.getSubmissions(filters);
      setSubmissions(Array.isArray(submissionsResponse.results) ? submissionsResponse.results : []);
    } catch (error) {
      console.error('Load data error:', error);
      setError(error instanceof Error ? error.message : 'Failed to load data');
      setSubmissions([]);
    }
  };

  const loadStats = async () => {
    try {
      console.log('Loading stats with filters:', filters);
      const statsResponse = await adminApiClient.getStats(filters);
      console.log('Stats response:', statsResponse);
      
      // 🔧 FIXED: Handle response format without TypeScript errors
      setStats({
        ...DEFAULT_STATS,
        ...statsResponse,
        service_type_breakdown: statsResponse.service_type_breakdown || {},
        country_breakdown: statsResponse.country_breakdown || {},
        issue_timeframe_breakdown: statsResponse.issue_timeframe_breakdown || {},
        daily_submissions: Array.isArray(statsResponse.daily_submissions) ? statsResponse.daily_submissions : [],
        date_range: statsResponse.date_range || DEFAULT_STATS.date_range
      });
    } catch (error) {
      console.error('Load stats error:', error);
      setError(error instanceof Error ? error.message : 'Failed to load stats');
      setStats(DEFAULT_STATS);
    }
  };

  const loadFilterOptions = async () => {
    try {
      const options = await adminApiClient.getFilterOptions();
      console.log('Filter options response:', options);
      
      // 🔧 FIXED: Handle response format without TypeScript errors
      setFilterOptions({
        ...DEFAULT_FILTER_OPTIONS,
        ...options,
        service_types: Array.isArray(options.service_types) ? options.service_types : [],
        issue_timeframes: Array.isArray(options.issue_timeframes) ? options.issue_timeframes : [],
        acknowledgments: Array.isArray(options.acknowledgments) ? options.acknowledgments : [],
        primary_goals: Array.isArray(options.primary_goals) ? options.primary_goals : [],
        heard_abouts: Array.isArray(options.heard_abouts) ? options.heard_abouts : [],
        communication_methods: Array.isArray(options.communication_methods) ? options.communication_methods : [],
        countries: Array.isArray(options.countries) ? options.countries : []
      });
    } catch (error) {
      console.error('Failed to load filter options:', error);
      setFilterOptions(DEFAULT_FILTER_OPTIONS);
    }
  };

  const handleDownload = async () => {
    try {
      setIsDownloading(true);
      setError('');
      setSuccessMessage('');
      
      console.log('Starting Excel download with filters:', filters);
      
      const blob = await adminApiClient.downloadSubmissions(filters);
      
      // Verify the blob
      if (!blob || blob.size === 0) {
        throw new Error('Downloaded file is empty');
      }
      
      console.log('Download successful, blob size:', blob.size, 'type:', blob.type);
      
      // Create download link with proper filename
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      
      // Generate filename with timestamp
      const now = new Date();
      const timestamp = now.toISOString().slice(0, 19).replace(/[:-]/g, '').replace('T', '_');
      const filename = `form_submissions_${timestamp}.xlsx`;
      
      link.download = filename;
      
      // Trigger download
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
      
      // Show success message
      setSuccessMessage(`Excel file "${filename}" downloaded successfully!`);
      
    } catch (error) {
      console.error('Download error:', error);
      const errorMessage = error instanceof Error ? error.message : 'Failed to download submissions';
      setError(`Download failed: ${errorMessage}`);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleViewSubmission = async (id: number) => {
    try {
      const detail = await adminApiClient.getSubmissionDetail(id);
      setSelectedSubmission(detail);
    } catch (error) {
      setError('Failed to load submission details');
    }
  };

  const handleDeleteSubmission = async (id: number) => {
    if (!confirm('Are you sure you want to delete this submission?')) return;
    
    try {
      await adminApiClient.deleteSubmission(id);
      setSubmissions(prev => prev.filter(s => s.id !== id));
      setSuccessMessage('Submission deleted successfully');
      setError('');
      
      // 🔧 FIXED: Reload stats after deletion
      await loadStats();
    } catch (error) {
      setError('Failed to delete submission');
    }
  };

  const handleDeleteAll = async () => {
    if (deleteConfirmation !== 'delete_permanently') {
      setError('Please type "delete_permanently" to confirm');
      return;
    }

    try {
      setIsDeleting(true);
      await adminApiClient.deleteAllSubmissions(deleteConfirmation);
      setSubmissions([]);
      setShowDeleteAllModal(false);
      setDeleteConfirmation('');
      setSuccessMessage('All submissions deleted successfully');
      setError('');
      
      // 🔧 FIXED: Reload stats after bulk deletion
      await loadStats();
    } catch (error) {
      setError('Failed to delete all submissions');
    } finally {
      setIsDeleting(false);
    }
  };

  const handleFilterChange = (key: keyof SubmissionFilters, value: string) => {
    setFilters(prev => ({
      ...prev,
      [key]: value || undefined
    }));
  };

  const clearFilters = () => {
    setFilters({});
  };

  const formatDate = (dateString: string) => {
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return 'Invalid Date';
    }
  };

  const handleTabChange = (tab: 'submissions' | 'analytics') => {
    setActiveTab(tab);
    // 🔧 FIXED: Always ensure stats are loaded when switching to analytics
    if (tab === 'analytics') {
      loadStats();
    }
  };

  if (isLoading) {
    return (
      <div className="min-h-screen bg-gray-50 flex items-center justify-center">
        <div className="text-center">
          <Loader className="w-8 h-8 animate-spin text-blue-500 mx-auto mb-4" />
          <p className="text-gray-600">Loading dashboard...</p>
        </div>
      </div>
    );
  }

  // Submission detail modal
  if (selectedSubmission) {
    return (
      <div className="min-h-screen bg-gray-50 p-6">
        <div className="max-w-4xl mx-auto">
          <div className="bg-white rounded-xl shadow-lg p-8">
            <div className="flex justify-between items-center mb-6">
              <h2 className="text-2xl font-bold text-gray-800">Submission Details</h2>
              <div className="flex space-x-2">
                <button
                  onClick={() => handleDeleteSubmission(selectedSubmission.id)}
                  className="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors flex items-center space-x-2"
                >
                  <Trash2 className="w-4 h-4" />
                  <span>Delete</span>
                </button>
                <button
                  onClick={() => setSelectedSubmission(null)}
                  className="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors"
                >
                  Back to Dashboard
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-gray-700">Contact Information</h3>
                <div className="space-y-2">
                  <p><span className="font-medium">Name:</span> {selectedSubmission.name || 'N/A'}</p>
                  <p><span className="font-medium">Email:</span> {selectedSubmission.email || 'N/A'}</p>
                  <p><span className="font-medium">Phone:</span> {selectedSubmission.phone || 'N/A'}</p>
                  <p><span className="font-medium">Country:</span> {selectedSubmission.country || 'N/A'}</p>
                  <p><span className="font-medium">Submitted:</span> {selectedSubmission.submitted_at ? formatDate(selectedSubmission.submitted_at) : 'N/A'}</p>
                  {selectedSubmission.ip_address && (
                    <p><span className="font-medium">IP Address:</span> {selectedSubmission.ip_address}</p>
                  )}
                </div>
              </div>
            </div>

            <div className="space-y-6">
              <h3 className="text-lg font-semibold text-gray-700">Form Responses</h3>
              
              <div className="space-y-4">
                {selectedSubmission.step1 && (
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="font-medium text-gray-700 mb-2">Company Name:</p>
                    <p className="text-gray-600">{selectedSubmission.step1}</p>
                  </div>
                )}
                
                {selectedSubmission.step2 && (
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="font-medium text-gray-700 mb-2">Service Type:</p>
                    <p className="text-gray-600">{selectedSubmission.step2}</p>
                  </div>
                )}
                
                {selectedSubmission.step3 && (
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="font-medium text-gray-700 mb-2">When Issue Occurred:</p>
                    <p className="text-gray-600">{selectedSubmission.step3}</p>
                  </div>
                )}
                
                {selectedSubmission.step4 && (
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="font-medium text-gray-700 mb-2">Company Acknowledgment:</p>
                    <p className="text-gray-600">{selectedSubmission.step4}</p>
                  </div>
                )}
                
                {selectedSubmission.step5 && (
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="font-medium text-gray-700 mb-2">Primary Goal:</p>
                    <p className="text-gray-600">{selectedSubmission.step5}</p>
                  </div>
                )}
                
                {selectedSubmission.step6 && (
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="font-medium text-gray-700 mb-2">How They Heard About Us:</p>
                    <p className="text-gray-600">{selectedSubmission.step6}</p>
                  </div>
                )}
                
                {selectedSubmission.step7 && (
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="font-medium text-gray-700 mb-2">Preferred Communication:</p>
                    <p className="text-gray-600">{selectedSubmission.step7}</p>
                  </div>
                )}
                
                {selectedSubmission.step8 && (
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <p className="font-medium text-gray-700 mb-2">Case Summary:</p>
                    <p className="text-gray-600 whitespace-pre-wrap">{selectedSubmission.step8}</p>
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto p-6">
        {/* Success Message */}
        {successMessage && (
          <div className="mb-6 p-4 bg-green-50 border border-green-200 rounded-lg flex items-center space-x-2">
            <CheckCircle className="w-5 h-5 text-green-500 flex-shrink-0" />
            <span className="text-green-700">{successMessage}</span>
            <button onClick={() => setSuccessMessage('')} className="ml-auto text-green-500 hover:text-green-700">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Error Message */}
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center space-x-2">
            <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0" />
            <span className="text-red-700">{error}</span>
            <button onClick={() => setError('')} className="ml-auto text-red-500 hover:text-red-700">
              <X className="w-4 h-4" />
            </button>
          </div>
        )}

        {/* Tab Navigation */}
        <div className="mb-6">
          <div className="border-b border-gray-200">
            <nav className="-mb-px flex space-x-8">
              <button
                onClick={() => handleTabChange('submissions')}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'submissions'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <FileText className="w-5 h-5 inline mr-2" />
                Submissions
              </button>
              <button
                onClick={() => handleTabChange('analytics')}
                className={`py-2 px-1 border-b-2 font-medium text-sm ${
                  activeTab === 'analytics'
                    ? 'border-blue-500 text-blue-600'
                    : 'border-transparent text-gray-500 hover:text-gray-700 hover:border-gray-300'
                }`}
              >
                <BarChart3 className="w-5 h-5 inline mr-2" />
                Analytics
              </button>
            </nav>
          </div>
        </div>

        {/* Analytics Tab */}
        {activeTab === 'analytics' && (
          <div className="space-y-6">
            {/* Date Range Selector */}
            <div className="bg-white p-6 rounded-xl shadow-lg">
              <h3 className="text-lg font-semibold mb-4">Date Range Analysis</h3>
              <div className="flex flex-wrap gap-2 mb-4">
                <button
                  onClick={() => handleFilterChange('date_preset', 'today')}
                  className={`px-4 py-2 rounded-lg ${
                    filters.date_preset === 'today' ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  Today
                </button>
                <button
                  onClick={() => handleFilterChange('date_preset', '1_week')}
                  className={`px-4 py-2 rounded-lg ${
                    filters.date_preset === '1_week' ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  1 Week
                </button>
                <button
                  onClick={() => handleFilterChange('date_preset', '2_weeks')}
                  className={`px-4 py-2 rounded-lg ${
                    filters.date_preset === '2_weeks' ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  2 Weeks
                </button>
                <button
                  onClick={() => handleFilterChange('date_preset', '30_days')}
                  className={`px-4 py-2 rounded-lg ${
                    filters.date_preset === '30_days' ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  30 Days
                </button>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">From Date</label>
                  <input
                    type="date"
                    value={filters.date_from || ''}
                    onChange={(e) => handleFilterChange('date_from', e.target.value)}
                    className="w-full p-2 border border-gray-300 rounded-lg"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">To Date</label>
                  <input
                    type="date"
                    value={filters.date_to || ''}
                    onChange={(e) => handleFilterChange('date_to', e.target.value)}
                    className="w-full p-2 border border-gray-300 rounded-lg"
                  />
                </div>
              </div>
            </div>

            {/* Stats Cards */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
              <div className="bg-white p-6 rounded-xl shadow-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-600 text-sm">Total Submissions</p>
                    <p className="text-3xl font-bold text-gray-800">{safeStats.total_submissions}</p>
                  </div>
                  <Users className="w-8 h-8 text-blue-500" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-xl shadow-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-600 text-sm">Service Types</p>
                    <p className="text-3xl font-bold text-gray-800">{Object.keys(safeStats.service_type_breakdown).length}</p>
                  </div>
                  <FileText className="w-8 h-8 text-green-500" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-xl shadow-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-600 text-sm">Countries</p>
                    <p className="text-3xl font-bold text-gray-800">{Object.keys(safeStats.country_breakdown).length}</p>
                  </div>
                  <TrendingUp className="w-8 h-8 text-purple-500" />
                </div>
              </div>

              <div className="bg-white p-6 rounded-xl shadow-lg">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-gray-600 text-sm">Period</p>
                    <p className="text-lg font-bold text-gray-800">{safeStats.date_range.preset || 'Custom'}</p>
                  </div>
                  <Calendar className="w-8 h-8 text-orange-500" />
                </div>
              </div>
            </div>

            {/* Breakdown Charts */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-white p-6 rounded-xl shadow-lg">
                <h3 className="text-lg font-semibold mb-4">Service Types</h3>
                <div className="space-y-3">
                  {Object.keys(safeStats.service_type_breakdown).length > 0 ? (
                    Object.entries(safeStats.service_type_breakdown).map(([type, count]) => (
                      <div key={type} className="flex justify-between items-center">
                        <span className="text-gray-700 capitalize">{type}</span>
                        <span className="bg-blue-100 text-blue-800 px-2 py-1 rounded-full text-sm font-medium">
                          {count}
                        </span>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500 text-sm">No data available</p>
                  )}
                </div>
              </div>

              <div className="bg-white p-6 rounded-xl shadow-lg">
                <h3 className="text-lg font-semibold mb-4">Countries</h3>
                <div className="space-y-3">
                  {Object.keys(safeStats.country_breakdown).length > 0 ? (
                    Object.entries(safeStats.country_breakdown).map(([country, count]) => (
                      <div key={country} className="flex justify-between items-center">
                        <span className="text-gray-700">{country}</span>
                        <span className="bg-green-100 text-green-800 px-2 py-1 rounded-full text-sm font-medium">
                          {count}
                        </span>
                      </div>
                    ))
                  ) : (
                    <p className="text-gray-500 text-sm">No data available</p>
                  )}
                </div>
              </div>
            </div>

            {/* Issue Timeframes */}
            <div className="bg-white p-6 rounded-xl shadow-lg">
              <h3 className="text-lg font-semibold mb-4">Issue Timeframes</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {Object.keys(safeStats.issue_timeframe_breakdown).length > 0 ? (
                  Object.entries(safeStats.issue_timeframe_breakdown).map(([timeframe, count]) => (
                    <div key={timeframe} className="flex justify-between items-center p-3 bg-gray-50 rounded-lg">
                      <span className="text-gray-700">{timeframe}</span>
                      <span className="bg-purple-100 text-purple-800 px-2 py-1 rounded-full text-sm font-medium">
                        {count}
                      </span>
                    </div>
                  ))
                ) : (
                  <p className="text-gray-500 text-sm">No data available</p>
                )}
              </div>
            </div>

            {/* Daily Submissions Chart */}
            {safeStats.daily_submissions.length > 0 && (
              <div className="bg-white p-6 rounded-xl shadow-lg">
                <h3 className="text-lg font-semibold mb-4">Daily Submissions</h3>
                <div className="h-64 flex items-end space-x-2">
                  {safeStats.daily_submissions.map((day) => (
                    <div key={day.date} className="flex-1 flex flex-col items-center">
                      <div 
                        className="bg-blue-500 w-full rounded-t"
                        style={{ 
                          height: `${Math.max((day.count / Math.max(...safeStats.daily_submissions.map(d => d.count))) * 200, 5)}px` 
                        }}
                      ></div>
                      <div className="text-xs text-gray-500 mt-2 transform -rotate-45 origin-top-left">
                        {new Date(day.date).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}
                      </div>
                      <div className="text-xs font-medium text-gray-700">{day.count}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Submissions Tab */}
        {activeTab === 'submissions' && (
          <>
            {/* Actions and Filters */}
            <div className="flex flex-col lg:flex-row justify-between items-start lg:items-center mb-6 space-y-4 lg:space-y-0">
              <div className="flex items-center space-x-4">
                <h2 className="text-2xl font-bold text-gray-800">Submissions</h2>
                <span className="bg-blue-100 text-blue-800 px-3 py-1 rounded-full text-sm font-medium">
                  {safeSubmissions.length} found
                </span>
              </div>
              
              <div className="flex flex-wrap items-center space-x-2 space-y-2 lg:space-y-0">
                <button
                  onClick={() => setShowFilters(!showFilters)}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-lg transition-colors ${
                    showFilters ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200'
                  }`}
                >
                  <Filter className="w-5 h-5" />
                  <span>Filters</span>
                </button>
                
                <button
                  onClick={handleDownload}
                  disabled={isDownloading}
                  className="flex items-center space-x-2 px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 disabled:opacity-50 transition-colors"
                >
                  {isDownloading ? (
                    <Loader className="w-5 h-5 animate-spin" />
                  ) : (
                    <Download className="w-5 h-5" />
                  )}
                  <span>{isDownloading ? 'Downloading...' : 'Download Excel'}</span>
                </button>
                
                <button
                  onClick={() => setShowDeleteAllModal(true)}
                  className="flex items-center space-x-2 px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition-colors"
                >
                  <Trash2 className="w-5 h-5" />
                  <span>Delete All</span>
                </button>
              </div>
            </div>

            {/* Filters Panel */}
            {showFilters && (
              <div className="bg-white p-6 rounded-xl shadow-lg mb-6">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-lg font-semibold">Filters</h3>
                  <button
                    onClick={clearFilters}
                    className="text-blue-500 hover:text-blue-700 text-sm font-medium"
                  >
                    Clear All
                  </button>
                </div>
                
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Search</label>
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                      <input
                        type="text"
                        value={filters.search || ''}
                        onChange={(e) => handleFilterChange('search', e.target.value)}
                        placeholder="Search name, email, company..."
                        className="w-full pl-10 p-2 border border-gray-300 rounded-lg"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Service Type</label>
                    <select
                      value={filters.service_type || ''}
                      onChange={(e) => handleFilterChange('service_type', e.target.value)}
                      className="w-full p-2 border border-gray-300 rounded-lg"
                    >
                      <option value="">All Service Types</option>
                      {safeFilterOptions.service_types.map((type, index) => (
                        <option key={`${type}-${index}`} value={type}>{type}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Issue Timeframe</label>
                    <select
                      value={filters.issue_timeframe || ''}
                      onChange={(e) => handleFilterChange('issue_timeframe', e.target.value)}
                      className="w-full p-2 border border-gray-300 rounded-lg"
                    >
                      <option value="">All Timeframes</option>
                      {safeFilterOptions.issue_timeframes.map((timeframe, index) => (
                        <option key={`${timeframe}-${index}`} value={timeframe}>{timeframe}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Country</label>
                    <select
                      value={filters.country || ''}
                      onChange={(e) => handleFilterChange('country', e.target.value)}
                      className="w-full p-2 border border-gray-300 rounded-lg"
                    >
                      <option value="">All Countries</option>
                      {safeFilterOptions.countries.map((country, index) => (
                        <option key={`${country.code}-${index}`} value={country.code}>{country.display}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Primary Goal</label>
                    <select
                      value={filters.primary_goal || ''}
                      onChange={(e) => handleFilterChange('primary_goal', e.target.value)}
                      className="w-full p-2 border border-gray-300 rounded-lg"
                    >
                      <option value="">All Goals</option>
                      {safeFilterOptions.primary_goals.map((goal, index) => (
                        <option key={`${goal}-${index}`} value={goal}>{goal}</option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Communication Method</label>
                    <select
                      value={filters.communication_method || ''}
                      onChange={(e) => handleFilterChange('communication_method', e.target.value)}
                      className="w-full p-2 border border-gray-300 rounded-lg"
                    >
                      <option value="">All Methods</option>
                      {safeFilterOptions.communication_methods.map((method, index) => (
                        <option key={`${method}-${index}`} value={method}>{method}</option>
                      ))}
                    </select>
                  </div>
                </div>
              </div>
            )}

            {/* Submissions Table */}
            <div className="bg-white rounded-xl shadow-lg overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Contact
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Summary
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Date
                      </th>
                      <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">
                        Actions
                      </th>
                    </tr>
                  </thead>
                  <tbody className="bg-white divide-y divide-gray-200">
                    {safeSubmissions.map((submission) => (
                      <tr key={submission.id} className="hover:bg-gray-50">
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div>
                            <div className="text-sm font-medium text-gray-900">{submission.name || 'N/A'}</div>
                            <div className="text-sm text-gray-500">{submission.email || 'N/A'}</div>
                            <div className="text-sm text-gray-500">{submission.phone || 'N/A'}</div>
                          </div>
                        </td>
                        <td className="px-6 py-4">
                          <div className="text-sm text-gray-900 max-w-xs truncate">
                            {submission.short_summary || 'No summary available'}
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap">
                          <div className="flex items-center">
                            <Calendar className="w-4 h-4 text-gray-400 mr-2" />
                            <span className="text-sm text-gray-500">
                              {submission.submitted_at ? formatDate(submission.submitted_at) : 'N/A'}
                            </span>
                          </div>
                        </td>
                        <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                          <div className="flex items-center space-x-2">
                            <button
                              onClick={() => handleViewSubmission(submission.id)}
                              className="flex items-center space-x-1 text-blue-600 hover:text-blue-900 transition-colors"
                            >
                              <Eye className="w-4 h-4" />
                              <span>View</span>
                            </button>
                            <button
                              onClick={() => handleDeleteSubmission(submission.id)}
                              className="flex items-center space-x-1 text-red-600 hover:text-red-900 transition-colors"
                            >
                              <Trash2 className="w-4 h-4" />
                              <span>Delete</span>
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>

            {safeSubmissions.length === 0 && (
              <div className="text-center py-12">
                <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
                <p className="text-gray-600">No submissions found</p>
                {Object.keys(filters).length > 0 && (
                  <button
                    onClick={clearFilters}
                    className="mt-2 text-blue-500 hover:text-blue-700 font-medium"
                  >
                    Clear filters to see all submissions
                  </button>
                )}
              </div>
            )}
          </>
        )}

        {/* Delete All Modal */}
        {showDeleteAllModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
            <div className="bg-white rounded-xl p-8 max-w-md w-full mx-4">
              <div className="flex items-center space-x-3 mb-4">
                <AlertTriangle className="w-8 h-8 text-red-500" />
                <h3 className="text-xl font-bold text-gray-800">Delete All Submissions</h3>
              </div>
              
              <p className="text-gray-600 mb-6">
                This action cannot be undone. All submissions will be permanently deleted.
                Type <strong>"delete_permanently"</strong> to confirm.
              </p>
              
              <input
                type="text"
                value={deleteConfirmation}
                onChange={(e) => setDeleteConfirmation(e.target.value)}
                placeholder="Type: delete_permanently"
                className="w-full p-3 border border-gray-300 rounded-lg mb-6"
              />
              
              <div className="flex justify-end space-x-4">
                <button
                  onClick={() => {
                    setShowDeleteAllModal(false);
                    setDeleteConfirmation('');
                  }}
                  className="px-4 py-2 bg-gray-300 text-gray-700 rounded-lg hover:bg-gray-400 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={handleDeleteAll}
                  disabled={deleteConfirmation !== 'delete_permanently' || isDeleting}
                  className="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 disabled:opacity-50 transition-colors flex items-center space-x-2"
                >
                  {isDeleting && <Loader className="w-4 h-4 animate-spin" />}
                  <span>{isDeleting ? 'Deleting...' : 'Delete All'}</span>
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;