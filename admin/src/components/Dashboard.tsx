import React, { useState, useEffect } from 'react';
import { 
  Users, 
  FileText, 
  Download, 
  Calendar, 
  TrendingUp,
  AlertCircle,
  Loader,
  Eye
} from 'lucide-react';
import { adminApiClient, type Submission, type SubmissionStats, type SubmissionDetail } from '../utils/api';

const Dashboard: React.FC = () => {
  const [submissions, setSubmissions] = useState<Submission[]>([]);
  const [stats, setStats] = useState<SubmissionStats | null>(null);
  const [selectedSubmission, setSelectedSubmission] = useState<SubmissionDetail | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isDownloading, setIsDownloading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      setIsLoading(true);
      const [submissionsResponse, statsResponse] = await Promise.all([
        adminApiClient.getSubmissions(),
        adminApiClient.getStats(),
      ]);
      
      setSubmissions(submissionsResponse.results);
      setStats(statsResponse);
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Failed to load data');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDownload = async () => {
    try {
      setIsDownloading(true);
      const blob = await adminApiClient.downloadSubmissions();
      
      // Create download link
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `form_submissions_${new Date().toISOString().split('T')[0]}.xlsx`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);
    } catch (error) {
      setError('Failed to download submissions');
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

  const formatDate = (dateString: string) => {
    return new Date(dateString).toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
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
              <button
                onClick={() => setSelectedSubmission(null)}
                className="px-4 py-2 bg-gray-500 text-white rounded-lg hover:bg-gray-600 transition-colors"
              >
                Back to Dashboard
              </button>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-gray-700">Contact Information</h3>
                <div className="space-y-2">
                  <p><span className="font-medium">Name:</span> {selectedSubmission.name}</p>
                  <p><span className="font-medium">Email:</span> {selectedSubmission.email}</p>
                  <p><span className="font-medium">Phone:</span> {selectedSubmission.phone}</p>
                  <p><span className="font-medium">Country:</span> {selectedSubmission.country}</p>
                  <p><span className="font-medium">Submitted:</span> {formatDate(selectedSubmission.submitted_at)}</p>
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
        {error && (
          <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded-lg flex items-center space-x-2">
            <AlertCircle className="w-5 h-5 text-red-500 flex-shrink-0" />
            <span className="text-red-700">{error}</span>
          </div>
        )}

        {/* Stats Cards */}
        {stats && (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
            <div className="bg-white p-6 rounded-xl shadow-lg">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-600 text-sm">Total Submissions</p>
                  <p className="text-3xl font-bold text-gray-800">{stats.total_submissions}</p>
                </div>
                <Users className="w-8 h-8 text-blue-500" />
              </div>
            </div>

            <div className="bg-white p-6 rounded-xl shadow-lg">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-600 text-sm">Last 30 Days</p>
                  <p className="text-3xl font-bold text-gray-800">{stats.recent_submissions_30_days}</p>
                </div>
                <TrendingUp className="w-8 h-8 text-green-500" />
              </div>
            </div>

            <div className="bg-white p-6 rounded-xl shadow-lg">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-gray-600 text-sm">Service Types</p>
                  <p className="text-3xl font-bold text-gray-800">{Object.keys(stats.service_type_breakdown).length}</p>
                </div>
                <FileText className="w-8 h-8 text-purple-500" />
              </div>
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex justify-between items-center mb-6">
          <h2 className="text-2xl font-bold text-gray-800">Recent Submissions</h2>
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
        </div>

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
                {submissions.map((submission) => (
                  <tr key={submission.id} className="hover:bg-gray-50">
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div>
                        <div className="text-sm font-medium text-gray-900">{submission.name}</div>
                        <div className="text-sm text-gray-500">{submission.email}</div>
                        <div className="text-sm text-gray-500">{submission.phone}</div>
                      </div>
                    </td>
                    <td className="px-6 py-4">
                      <div className="text-sm text-gray-900 max-w-xs truncate">
                        {submission.short_summary}
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap">
                      <div className="flex items-center">
                        <Calendar className="w-4 h-4 text-gray-400 mr-2" />
                        <span className="text-sm text-gray-500">
                          {formatDate(submission.submitted_at)}
                        </span>
                      </div>
                    </td>
                    <td className="px-6 py-4 whitespace-nowrap text-sm font-medium">
                      <button
                        onClick={() => handleViewSubmission(submission.id)}
                        className="flex items-center space-x-1 text-blue-600 hover:text-blue-900 transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                        <span>View</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {submissions.length === 0 && (
          <div className="text-center py-12">
            <FileText className="w-12 h-12 text-gray-400 mx-auto mb-4" />
            <p className="text-gray-600">No submissions yet</p>
          </div>
        )}
      </div>
    </div>
  );
};

export default Dashboard;