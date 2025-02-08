const express = require('express');
const axios = require('axios');
const whois = require('whois-json');
const { URL } = require('url');
const dotenv = require('dotenv');
dotenv.config();

const app = express();

async function getDomainAge(domain) {
  try {
    const domainInfo = await whois(domain);
    let creationDate = domainInfo.creationDate || domainInfo.createdDate || domainInfo.creation_date;
    if (Array.isArray(creationDate)) creationDate = creationDate[0];
    if (!creationDate) return 'No Data';
    const date = new Date(creationDate);
    if (isNaN(date.getTime())) return 'No Data';
    return Math.floor((Date.now() - date.getTime()) / (1000 * 60 * 60 * 24));
  } catch (e) {
    return 'No Data';
  }
}

async function checkGoogleSafeBrowsing(url) {
  const gsApiKey = process.env.GS_API_KEY;
  if (!gsApiKey) {
    return { safe: false, details: "API key missing" };
  }
  try {
    const response = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${gsApiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client: { clientId: 'phishing-detector', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }]
        }
      })
    });
    if (!response.ok) throw new Error('Safe Browsing API request failed');
    const data = await response.json();
    return {
      safe: !data.matches,
      details: data.matches 
                ? `Threats detected: ${data.matches.map(m => m.threatType).join(', ')}`
                : 'No known threats detected'
    };
  } catch (error) {
    return { safe: false, details: error.message };
  }
}

async function checkGemini(url, urlInfo) {
  try {
    const promptText = `Please perform a detailed analysis of the following URL for any potential phishing threats:
    URL: ${url}
    Domain: ${urlInfo.hostname}
    Path: ${urlInfo.pathname}
    Query Parameters: ${urlInfo.search}

    Consider the following aspects in your evaluation:
    1. Domain reputation and registration details.
    2. Similarity to known phishing patterns or scams.
    3. Presence of suspicious URL encodings or redirects.
    4. Abnormal structures in the URL indicating a potential threat.
    5. Any misleading content or cues that could deceive users.

    Respond using the exact format below:
    VERDICT: (SAFE/UNSAFE)
    CONFIDENCE: (0-100, where 100 indicates absolute certainty)
    CATEGORY: (Any valid category, e.g., Blog, Business, E-commerce, Informational, Portfolio, Personal, Non-profit, Entertainment, Social Media, Educational, Event, Membership, Online Forum, Community, Startup, Consulting, Booking, Petition, School, Hobby, Interactive, Wedding, Travel, Directory, Landing Page, News and Magazine, Memorial, Subscription, Kid-friendly)
    EXPLANATION: (A brief summary of the factors that influenced your evaluation)`;

    const response = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${process.env.GEMINI_API_KEY}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: promptText }] }]
      })
    });

    if (!response.ok) throw new Error('Gemini API request failed');
    const data = await response.json();
    if (!data.candidates || !data.candidates[0]?.content?.parts[0]?.text) {
      throw new Error('Invalid Gemini API response');
    }

    const result = data.candidates[0].content.parts[0].text;
    const [verdict, confidence, category, explanation] = parseGeminiResponse(result);
    if (!verdict || !confidence) throw new Error('Invalid Gemini response format');

    return {
      safe: verdict === 'SAFE' && parseInt(confidence, 10) > 80,
      category: category || 'Other',
      explanation: explanation || 'No detailed analysis available'
    };
  } catch (error) {
    return { 
      safe: false, 
      category: 'Other',
      explanation: 'AI analysis failed: ' + (error.message || 'Unknown error') 
    };
  }
}

function parseGeminiResponse(response) {
  try {
    const lines = response.split('\n');
    let verdict = 'UNSAFE';
    let confidence = '0';
    let category = 'Other';
    let explanation = '';

    lines.forEach(line => {
      const trimmedLine = line.trim();
      if (trimmedLine.startsWith('VERDICT:')) {
        verdict = trimmedLine.split(':')[1].trim().toUpperCase();
      } else if (trimmedLine.startsWith('CONFIDENCE:')) {
        confidence = trimmedLine.split(':')[1].trim().replace(/[^0-9]/g, '');
      } else if (trimmedLine.startsWith('CATEGORY:')) {
        category = trimmedLine.split(':')[1].trim();
      } else if (trimmedLine.startsWith('EXPLANATION:')) {
        explanation = trimmedLine.split(':').slice(1).join(':').trim();
      }
    });

    if (!verdict || !confidence || !explanation) {
      throw new Error('Invalid response format');
    }
    return [verdict, confidence, category, explanation];
  } catch (error) {
    return ['UNSAFE', '0', 'Other', 'Failed to parse AI response'];
  }
}

async function analyzeUrlContent(url) {
  try {
    const response = await fetch(url);
    const text = await response.text();
    
    const indicators = {
      // Form analysis
      hasPasswordField: {
        detected: /<input[^>]*type=["']password["'][^>]*>/i.test(text),
        weight: 15
      },
      hasLoginForm: {
        detected: /<form[^>]*>[\s\S]*?(?:login|signin|password)[\s\S]*?<\/form>/i.test(text),
        weight: 20
      },
      
      // Script analysis
      hasSuspiciousRedirects: {
        detected: /window\.location\s*=|document\.location\s*=|setTimeout\s*\([^)]*(?:location|redirect|url)/i.test(text),
        weight: 25
      },
      hasObfuscatedCode: {
        detected: /(eval|unescape|escape|atob|btoa)\s*\([^)]*\)|(function\s*\(\s*\)\s*{\s*[a-z$_]{1,2})/i.test(text),
        weight: 30
      },
      
      // Content analysis
      hasDataExfiltration: {
        detected: /XMLHttpRequest|fetch\s*\(|navigator\.sendBeacon|websocket/i.test(text),
        weight: 20
      },
      hasSuspiciousHeaders: {
        detected: /<h[1-6][^>]*>\s*(?:verify|confirm|secure|account|login|password|bank|wallet)/i.test(text),
        weight: 15
      },
      
      // Hidden elements
      hasHiddenFields: {
        detected: /<[^>]+(?:visibility:\s*hidden|display:\s*none|opacity:\s*0)[^>]*>.*?(?:password|email|account|card)/i.test(text),
        weight: 25
      }
    };

    const score = Object.values(indicators).reduce((total, { detected, weight }) => {
      return total + (detected ? weight : 0);
    }, 0);

    return {
      score: Math.min(score, 100),
      hasPhishingIndicators: score > 40
    };
  } catch (error) {
    console.error('Content analysis error:', error);
    return {
      score: 0,
      hasPhishingIndicators: false
    };
  }
}

/* --- Improved Scoring Algorithm --- */
function calculateOverallRisk({ safeBrowsingScore, geminiScore, domainRisk, contentScore }) {
  // Weights for each check (total sum = 1)
  const weights = {
    safeBrowsing: 0.35,
    gemini: 0.20,
    domain: 0.25,
    content: 0.20
  };

  // Compute the weighted sum.
  const overallRiskScore =
    safeBrowsingScore * weights.safeBrowsing +
    geminiScore * weights.gemini +
    domainRisk * weights.domain +
    contentScore * weights.content;

  // Round off for clarity.
  return Math.round(overallRiskScore);
}

function generateSummary(overallRiskScore, geminiCategory) {
  const isReallySafe = overallRiskScore < 50;
  return {
    message: isReallySafe 
             ? 'This URL appears to be safe.' 
             : `Warning: This URL may be unsafe. Risk Score: ${overallRiskScore}`,
    category: geminiCategory,
    isReallySafe
  };
}

/* --- End Scoring Functions --- */

app.get('/api/check', async (req, res) => {
  let url = req.query.url;
  if (!url) return res.status(400).json({ error: 'No url parameter provided.' });
  if (!url.startsWith('http://') && !url.startsWith('https://')) url = 'http://' + url;

  let parsedUrl;
  try {
    parsedUrl = new URL(url);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL provided.' });
  }
  
  const domain = parsedUrl.hostname;
  const ageDays = await getDomainAge(domain);
  const isNewlyListed = ageDays !== 'No Data' && ageDays < 30;
  
  // Compute domain risk based on age.
  const domainRisk = (ageDays === 'No Data' || ageDays < 30) ? 80 : 20;

  // Handle redirects.
  let redirects = [];
  try {
    const response = await axios.get(url, { timeout: 10000, maxRedirects: 5 });
    const finalUrl = response.request.res.responseUrl;
    if (finalUrl && finalUrl !== url) {
      redirects = [url, finalUrl];
    }
  } catch (e) {
    redirects = [];
  }

  const safeBrowsingResult = await checkGoogleSafeBrowsing(url);
  const geminiResult = await checkGemini(url, parsedUrl);
  const contentAnalysisResult = await analyzeUrlContent(url);

  // Convert each result into a risk score out of 100.
  const safeBrowsingScore = safeBrowsingResult.safe ? 0 : 100;
  const geminiScore = geminiResult.safe ? 0 : 100;
  const contentScore = contentAnalysisResult.score;

  // Calculate overall risk.
  const overallRiskScore = calculateOverallRisk({
    safeBrowsingScore,
    geminiScore,
    domainRisk,
    contentScore
  });
  const summary = generateSummary(overallRiskScore, geminiResult.category);

  res.json({
    domain,
    domain_age_days: ageDays,
    is_newly_listed: isNewlyListed,
    google_malicious: !safeBrowsingResult.safe,
    safe_browsing_details: safeBrowsingResult.details,
    category: geminiResult.category,
    gemini_details: geminiResult.explanation,
    gemini_safe: geminiResult.safe,
    redirects,
    has_redirects: redirects.length > 0,
    content_analysis_score: contentAnalysisResult.score,
    has_phishing_indicators: contentAnalysisResult.hasPhishingIndicators,
    // Additional scoring information.
    overallRiskScore,
    summary
  });
});

module.exports = app;