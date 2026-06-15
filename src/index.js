const core = require('@actions/core');
const github = require('@actions/github');
const https = require('https');

async function apiRequest(method, path, body, apiKey, apiUrl) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, apiUrl);
    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`,
        'X-SecureScout-Action': 'true',
      }
    };
    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, body: data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function poll(scanId, apiKey, apiUrl, maxAttempts = 60) {
  for (let i = 0; i < maxAttempts; i++) {
    await new Promise(r => setTimeout(r, 5000));
    const res = await apiRequest('GET', `/api/scans/${scanId}`, null, apiKey, apiUrl);
    core.info(`Scan status: ${res.body.status} (attempt ${i + 1}/${maxAttempts})`);
    if (res.body.status === 'completed' || res.body.status === 'failed') {
      return res.body;
    }
  }
  throw new Error('Scan timed out after 5 minutes');
}

async function run() {
  try {
    const apiKey    = core.getInput('api_key', { required: true });
    const projectId = core.getInput('project_id', { required: true });
    const failOn    = core.getInput('fail_on') || 'critical';
    const apiUrl    = core.getInput('api_url') || 'https://api.getsecurescout.com';

    const context = github.context;
    const repoUrl = `https://github.com/${context.repo.owner}/${context.repo.repo}`;
    const ref     = context.ref;
    const sha     = context.sha;

    core.info(`🔐 SecureScout — scanning ${repoUrl}@${sha.slice(0, 7)}`);

    // Trigger scan
    const scanRes = await apiRequest('POST', '/api/scans/git', {
      project_id: projectId,
      repo_url: repoUrl,
      ref,
      sha,
    }, apiKey, apiUrl);

    if (scanRes.status !== 201) {
      throw new Error(`Failed to start scan: ${JSON.stringify(scanRes.body)}`);
    }

    const scanId = scanRes.body.id;
    core.info(`✅ Scan started: ${scanId}`);
    core.setOutput('scan_id', scanId);

    // Poll for completion
    const result = await poll(scanId, apiKey, apiUrl);

    if (result.status === 'failed') {
      throw new Error('Scan failed on the server.');
    }

    // Get findings
    const findingsRes = await apiRequest(
      'GET',
      `/api/findings?scan_id=${scanId}&project_id=${projectId}`,
      null, apiKey, apiUrl
    );

    const findings   = findingsRes.body.findings || [];
    const critical   = findings.filter(f => f.severity === 'critical').length;
    const high       = findings.filter(f => f.severity === 'high').length;
    const medium     = findings.filter(f => f.severity === 'medium').length;
    const low        = findings.filter(f => f.severity === 'low').length;

    core.setOutput('findings_count', findings.length);
    core.setOutput('critical_count', critical);

    core.info(`\n📊 SecureScout Results:`);
    core.info(`   🔴 Critical: ${critical}`);
    core.info(`   🟠 High:     ${high}`);
    core.info(`   🟡 Medium:   ${medium}`);
    core.info(`   🟢 Low:      ${low}`);
    core.info(`   🔗 Report:   https://app.getsecurescout.com`);

    const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
    const failRank     = severityRank[failOn] || 4;

    const shouldFail =
      (failRank <= 4 && critical > 0) ||
      (failRank <= 3 && high > 0)     ||
      (failRank <= 2 && medium > 0)   ||
      (failRank <= 1 && low > 0);

    // Send email notification if critical findings found
    if (critical > 0) {
      try {
        const emailRes = await apiRequest('POST', '/api/scans/notify', {
          scan_id: scanId,
          project_id: projectId,
          critical,
          high,
          medium,
          low,
          repo: `${context.repo.owner}/${context.repo.repo}`,
          ref: context.ref,
          sha: context.sha.slice(0, 7),
          workflow: context.workflow,
          run_url: `https://github.com/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`,
        }, apiKey, apiUrl);
        if (emailRes.status === 200) {
          core.info(`📧 Critical findings notification sent.`);
        }
      } catch (err) {
        core.warning(`Email notification failed: ${err.message}`);
      }
    }

    if (shouldFail) {
      core.setFailed(
        `❌ SecureScout found ${critical} critical, ${high} high vulnerabilities. ` +
        `Build failed (fail_on: ${failOn}). View report: https://app.getsecurescout.com`
      );
    } else {
      core.info(`✅ SecureScout scan passed. No ${failOn}+ severity findings.`);
    }

  } catch (err) {
    core.setFailed(`SecureScout Action failed: ${err.message}`);
  }
}

run();
