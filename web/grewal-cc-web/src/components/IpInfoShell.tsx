export default function IpInfoSkeleton() {
  return (
    <div className="mt-4 p-4 border border-gray-200 rounded-lg bg-gray-50 dark:border-gray-700 dark:bg-gray-800 animate-pulse">
      <div className="h-6 bg-gray-300 rounded-md dark:bg-gray-600 w-1/3 mb-4"></div>
      <div className="space-y-3">
        <div className="flex items-center space-x-2">
          <div className="h-4 bg-gray-300 rounded-md dark:bg-gray-700 w-1/4"></div>
          <div className="h-4 bg-gray-200 rounded-md dark:bg-gray-500 w-1/2"></div>
        </div>
        <div className="flex items-center space-x-2">
          <div className="h-4 bg-gray-300 rounded-md dark:bg-gray-700 w-1/4"></div>
          <div className="h-4 bg-gray-200 rounded-md dark:bg-gray-500 w-3/4"></div>
        </div>
      </div>
    </div>
  );
}
