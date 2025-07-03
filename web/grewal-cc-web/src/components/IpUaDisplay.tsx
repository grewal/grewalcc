'use client';

import { useEffect, useState } from 'react';
import { fetchIpUaDataAction } from '@/app/actions';

interface DisplayData {
  ip: string;
  userAgent: string;
  error?: string;
}

export function IpUaDisplay() {
  const [data, setData] = useState<DisplayData | null>(null);

  useEffect(() => {
    async function fetchData() {
      const result = await fetchIpUaDataAction();
      setData(result);
    }

    fetchData();
  }, []);

  if (!data) {
    return (
      <div className="text-xs text-gray-500 mt-2">
        <p>IP: Loading...</p>
        <p>UA: Loading...</p>
      </div>
    );
  }

  return (
    <div className="text-xs text-gray-500 mt-2">
      <p>IP: {data.ip}</p>
      <p>UA: {data.userAgent}</p>
      {data.error && <p className="text-red-500">Error: {data.error}</p>}
    </div>
  );
}
