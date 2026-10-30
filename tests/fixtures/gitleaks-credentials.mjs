// Browser contract samples use independently evaluated upstream findings.
// Retired heuristic samples remain in credentials.mjs for negative tests.
import { readFileSync } from 'node:fs';
const fixture = name => JSON.parse(readFileSync(new URL(`./gitleaks-${name}.json`, import.meta.url), 'utf8'));
const providers = fixture('providers').examples, structured = fixture('structured').examples;
const collaboration = fixture('collaboration').examples, catalog = fixture('catalog').cases;
export const providerKey = providers['github-pat'][0];
const mask = 'xxxxxxxxxx';
const cases = Object.entries(providers).map(([name, values]) => ({ name, input: `Inspect ${values[0]}`, secrets: [values[0]] }));
for (const [name, values] of Object.entries(structured)) cases.push({ name, input: values[0], secrets: [values[0]] });
cases.push(...fixture('curl').cases.filter(item => item.name.startsWith('example ')).slice(0, 2));
for (const name of ['slack-bot-token', 'slack-app-token', 'stripe-access-token', 'npm-access-token']) {
  const value = collaboration[name][0];
  cases.push({ name, input: value, secrets: [value] });
}
for (const id of ['azure-ad-client-secret', 'gitlab-pat', 'databricks-api-token', 'digitalocean-access-token',
  'sendgrid-api-token', 'twilio-api-key', 'postman-api-token', 'shopify-access-token']) {
  const item = catalog.find(item => item.ruleId === id && item.secrets.length);
  cases.push({ ...item, name: id });
}
export const credentialCases = cases.map(item => {
  const input = item.input.replace(/[\r\f]/g, '\n'), secrets = (item.browserSecrets ?? item.secrets).map(value => value.replace(/[\r\f]/g, '\n'));
  let masked = input, cursor = 0;
  for (const secret of secrets) {
    const start = masked.indexOf(secret, cursor);
    if (start < 0) throw new Error(`Missing reference value: ${item.name}`);
    masked = masked.slice(0, start) + mask + masked.slice(start + secret.length);
    cursor = start + mask.length;
  }
  return { name: item.name, input, masked, count: secrets.length };
});
