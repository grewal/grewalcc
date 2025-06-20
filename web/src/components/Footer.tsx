// File: web/src/components/Footer.tsx
export default function Footer() {
  const currentYear = new Date().getFullYear();
  return (
    <footer className="bg-gray-900 text-gray-400 py-6 mt-12">
      <div className="container mx-auto text-center">
        <p>© {currentYear} Grewal.cc - All Rights Reserved - {currentYear} </p>
      </div>
    </footer>
  );
}
