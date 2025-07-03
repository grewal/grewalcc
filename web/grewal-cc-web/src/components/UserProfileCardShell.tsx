export function UserProfileCardShell() {
  return (
    <div className="max-w-md mx-auto bg-gray-800 rounded-xl shadow-md overflow-hidden md:max-w-2xl border border-gray-700">
      <div className="p-8 animate-pulse">
        <div className="h-4 bg-gray-700 rounded w-1/4"></div>
        
        <div className="h-8 bg-gray-700 rounded w-3/4 mt-3"></div>
        
        <div className="mt-4 space-y-2">
          <div className="h-4 bg-gray-700 rounded w-full"></div>
          <div className="h-4 bg-gray-700 rounded w-5/6"></div>
        </div>

        <div className="h-4 bg-gray-700 rounded w-1/2 mt-4"></div>

        <div className="mt-6">
            <div className="h-4 bg-gray-700 rounded w-1/5 mb-3"></div>
            <div className="flex flex-wrap gap-2">
                <div className="h-6 bg-gray-700 rounded-full w-20"></div>
                <div className="h-6 bg-gray-700 rounded-full w-28"></div>
                <div className="h-6 bg-gray-700 rounded-full w-24"></div>
            </div>
        </div>
      </div>
    </div>
  );
}
