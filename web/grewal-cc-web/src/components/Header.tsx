export default function Header() {
  return (
    <header className="bg-gray-900 text-white shadow-sm">
      <div className="container mx-auto px-4 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <h1 className="text-xl font-bold">Grewal.cc</h1>
          </div>
          <nav className="hidden md:flex space-x-6">
            <a 
              href="/" 
              className="text-gray-300 hover:text-white transition-colors duration-200"
            >
              Home
            </a>
          </nav>
        </div>
      </div>
    </header>
  );
}
