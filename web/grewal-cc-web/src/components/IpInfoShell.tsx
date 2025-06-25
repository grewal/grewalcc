export default function IpInfoShell() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="flex items-center justify-between p-3 bg-gray-100 dark:bg-gray-700 rounded">
        <span className="text-gray-600 dark:text-gray-300 font-medium">Your IP:</span>
        <div className="h-4 bg-gray-300 dark:bg-gray-600 rounded w-32"></div>
      </div>
      
      <div className="flex items-center justify-between p-3 bg-gray-100 dark:bg-gray-700 rounded">
        <span className="text-gray-600 dark:text-gray-300 font-medium">Your Browser:</span>
        <div className="h-4 bg-gray-300 dark:bg-gray-600 rounded w-48"></div>
      </div>
      
      <div className="flex items-center justify-center pt-2">
        <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-blue-600"></div>
        <span className="ml-2 text-sm text-gray-500 dark:text-gray-400">
          Loading your information...
        </span>
      </div>
    </div>
  );
}
