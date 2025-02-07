const express = require('express');
const axios = require('axios');
const whois = require('whois-json');
const { URL } = require('url');
const dotenv = require('dotenv');
dotenv.config();

const app = express();

function encodeUrl(url) {
  return Buffer.from(url).toString('base64').replace(/=*$/, '');
}

async function checkMalicious(url) {
  const vtApiKey = process.env.VT_API_KEY;
  if (!vtApiKey) {
    console.log("VirusTotal API key not found.");
    return false;
  }
  const urlId = encodeUrl(url);
  const headers = { "x-apikey": vtApiKey };
  const vtUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
  try {
    const response = await axios.get(vtUrl, { headers, timeout: 10000 });
    if (response.status !== 200) {
      console.log(`Error: VirusTotal API request failed with status code ${response.status}`);
      return false;
    }
    const data = response.data;
    const stats = data.data.attributes.last_analysis_stats || {};
    return (stats.malicious || 0) > 0 || (stats.suspicious || 0) > 0;
  } catch (e) {
    console.log(`Error: ${e.message}`);
    return false;
  }
}

async function getSiteCategory(url) {
  const vtApiKey = process.env.VT_API_KEY;
  if (!vtApiKey) {
    return "Unknown";
  }
  const urlId = encodeUrl(url);
  const headers = { "x-apikey": vtApiKey };
  const vtUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;
  try {
    const response = await axios.get(vtUrl, { headers, timeout: 10000 });
    if (response.status === 200) {
      const data = response.data;
      const categories = data.data.attributes.categories || {};
      if (Object.keys(categories).length > 0) {
        return categories[Object.keys(categories)[0]].replace(" (alphaMountain.ai)", "");
      }
    }
    return "Unknown";
  } catch (e) {
    console.log(`Error: ${e.message}`);
    return "Unknown";
  }
}

async function getDomainAge(domain) {
  try {
    const domainInfo = await whois(domain);
    console.log("WHOIS data:", domainInfo);
    let creationDate = domainInfo.creationDate || domainInfo.createdDate || domainInfo.creation_date;
    if (Array.isArray(creationDate)) {
      creationDate = creationDate[0];
    }
    if (!creationDate) {
      console.log("Creation date not found in WHOIS data.");
      return null;
    }
    const date = new Date(creationDate);
    if (isNaN(date.getTime())) {
      console.log(`Invalid creation date format: ${creationDate}`);
      return null;
    }
    const ageDays = Math.floor((Date.now() - date.getTime()) / (1000 * 60 * 60 * 24));
    return ageDays;
  } catch (e) {
    console.log(`WHOIS error: ${e.message}`);
    return null;
  }
}

async function checkGoogleSafeBrowsing(url) {
  const gsApiKey = process.env.GS_API_KEY;
  if (!gsApiKey) {
    console.log("Google Safe Browsing API key not found.");
    return false;
  }
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${gsApiKey}`;
  const payload = {
    client: {
      clientId: "208397729537-qruu6dk9l8gdrqdp1fu1apa2a437rilo.apps.googleusercontent.com",
      clientVersion: "1.0"
    },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{"url": url}]
    }
  };
  try {
    const response = await axios.post(endpoint, payload, { timeout: 10000 });
    console.log("Google Safe Browsing response:", response.data);
    if (response.data && response.data.threatMatches && response.data.threatMatches.length > 0) {
      return true;
    }
    return false;
  } catch (e) {
    console.log(`Error: ${e.message}`);
    return false;
  }
}

app.get('/api/check', async (req, res) => {
  let url = req.query.url;
  if (!url) {
    return res.status(400).json({ error: 'No url parameter provided.' });
  }
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    url = 'http://' + url;
  }
  
  let domain;
  try {
    const parsedUrl = new URL(url);
    domain = parsedUrl.hostname;
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL provided.' });
  }
  
  const ageDays = await getDomainAge(domain);
  const isNewlyListed = ageDays !== null && ageDays < 30;
  const isMalicious = await checkMalicious(url);
  let redirects = [];
  let hasRedirects = false;
  try {
    const response = await axios.get(url, { timeout: 10000, maxRedirects: 5 });
    const finalUrl = response.request.res.responseUrl;
    if (finalUrl && finalUrl !== url) {
      redirects.push(finalUrl);
      hasRedirects = true;
    }
  } catch (e) {
    console.log(`Redirect check error: ${e.message}`);
    redirects = [];
    hasRedirects = null;
  }
  const siteCategory = await getSiteCategory(url);
  const isGoogleMalicious = await checkGoogleSafeBrowsing(url);
  res.json({
    domain,
    domain_age_days: ageDays,
    is_newly_listed: isNewlyListed,
    is_malicious: isMalicious,
    google_malicious: isGoogleMalicious,
    redirects,
    has_redirects: hasRedirects,
    site_category: siteCategory
  });
});

module.exports = app;