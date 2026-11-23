async function extractFacebookMedia(fbUrl, type) {
  // বিকল্প ১: যদি আপনি Render Environment Variables-এ RAPIDAPI_KEY ও RAPIDAPI_HOST সেট করেন
  if (process.env.RAPIDAPI_KEY && process.env.RAPIDAPI_HOST) {
    const apiUrl = `https://${process.env.RAPIDAPI_HOST}/download?url=${encodeURIComponent(fbUrl)}`;
    const apiRes = await fetch(apiUrl, {
      method: "GET",
      headers: {
        "x-rapidapi-key": process.env.RAPIDAPI_KEY,
        "x-rapidapi-host": process.env.RAPIDAPI_HOST
      }
    });

    if (apiRes.ok) {
      const json = await apiRes.json();
      const hd = json.hd || json.links?.hd || null;
      const sd = json.sd || json.links?.sd || null;
      const single = json.url || json.downloadUrl || null;
      if (hd || sd || single) {
        return {
          title: json.title || `Facebook-${type}`,
          hd,
          sd,
          downloadUrl: !hd && !sd ? single : null
        };
      }
    }
  }

  // বিকল্প ২: পাবলিক পেজ থেকে playable_url / hd_src খোঁজার চেষ্টা (শুধুমাত্র পাবলিক কন্টেন্টের জন্য)
  const pageRes = await fetch(fbUrl, {
    headers: {
      "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
      "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      "Accept-Language": "en-US,en;q=0.9"
    }
  });

  if (!pageRes.ok) {
    throw new Error("Could not fetch public Facebook page.");
  }

  const html = await pageRes.text();

  const decodeEscapedUrl = (raw) => {
    if (!raw) return null;
    return raw
      .replace(/\\u0025/g, "%")
      .replace(/\\\//g, "/")
      .replace(/&amp;/g, "&");
  };

  const hdMatch =
    html.match(/"playable_url_quality_hd":"(https:[^"]+)"/) ||
    html.match(/"hd_src":"(https:[^"]+)"/);

  const sdMatch =
    html.match(/"playable_url":"(https:[^"]+)"/) ||
    html.match(/"sd_src":"(https:[^"]+)"/);

  const titleMatch = html.match(/<title>(.*?)<\/title>/i);

  const hd = decodeEscapedUrl(hdMatch?.[1]);
  const sd = decodeEscapedUrl(sdMatch?.[1]);
  const cleanTitle = titleMatch?.[1]
    ? titleMatch[1].replace(/\s*\|\s*Facebook.*$/i, "").trim()
    : `Facebook-${type}`;

  if (!hd && !sd) {
    return {
      title: cleanTitle,
      hd: null,
      sd: null,
      downloadUrl: null,
      error: "No downloadable public MP4 stream found. The video may be private, restricted, or blocked by Facebook from cloud server IPs."
    };
  }

  return {
    title: cleanTitle,
    hd,
    sd,
    downloadUrl: null
  };
}
