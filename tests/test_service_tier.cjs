// Offline behavioral checks of version-pinned request/UI gates.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const path = require('node:path');
const crypto = require('node:crypto');
const profile = JSON.parse(fs.readFileSync(path.join(__dirname, '../profiles', `${process.argv[3] ?? '26.1007.2314.0'}.json`), 'utf8'));
const names = profile.behavior_symbols ?? {request:'bga',auth_lookup:'_ga',requirements_lookup:'KPe',query_key:'Hd',converter:'oee',
  ui:'KVi',memo:'qVi',host:'G',host_atom:'Li',auth:'BYe',query:'Zs'};
let checks = 0;
async function main() {
  const edit = profile.edits[0];
  for (const auth of ['chatgpt', 'personalAccessToken', 'apikey', null]) {
    for (const fast of [true, false, undefined]) {
      for (const ultra of [true, false]) {
        for (const usePatched of [false, true]) {
          const calls = [];
          const requirements = { fast, ultra };
          const sandbox = {
            [names.auth_lookup]: async () => auth,
            [names.requirements_lookup]: async (manager, host, options) => {
              assert.equal(host, 'host'); assert.equal(options.priority, 'critical');
              return requirements;
            },
            [names.query_key]: 'requirements',
            [names.converter]: r => ({fast: r.fast !== false, ultrafast: r.ultra}),
          };
          const fn = vm.runInNewContext((usePatched ? edit.new : edit.old) + ';'+names.request, sandbox);
          const manager = { query: { setData: (...args) => calls.push(args) } };
          const result = await fn(manager, 'host');
          const allowed = usePatched || auth === 'chatgpt' || auth === 'personalAccessToken';
          assert.equal(result !== null, allowed);
          assert.equal(calls.length, allowed ? 1 : 0);
          if (allowed) {
            assert.equal(result.fast, fast !== false);
            assert.equal(result.ultrafast, ultra);
            assert.equal(calls[0][1].authMethod, auth);
          }
          checks++;
        }
      }
    }
  }
  for (const failing of [names.auth_lookup, names.requirements_lookup]) {
    const sandbox = {[names.auth_lookup]: async()=> 'apikey', [names.requirements_lookup]: async()=> ({}),
      [names.query_key]:'query', [names.converter]:x=>x};
    sandbox[failing] = async()=>{throw Error('lookup failed')};
    const fn = vm.runInNewContext(edit.new+';'+names.request, sandbox);
    await assert.rejects(fn({query:{setData(){throw Error('unexpected cache write')}}},'host'), /lookup failed/);
    checks++;
  }
  if (process.argv[2]) {
    const original = fs.readFileSync(process.argv[2], 'utf8');
    assert.equal(crypto.createHash('sha256').update(original).digest('hex'), profile.original_sha256);
    let patched = original;
    for (const edit of profile.edits) {
      assert.equal(patched.split(edit.old).length - 1, 1);
      patched = patched.split(edit.old).join(edit.new);
    }
    assert.equal(crypto.createHash('sha256').update(patched).digest('hex'), profile.patched_sha256);
    for (const auth of ['chatgpt', 'personalAccessToken', 'apikey', null]) {
      for (const loading of [true, false]) {
        for (const pending of [true, false]) {
          for (const present of [true, false]) {
            const data = present ? {fast:false,ultrafast:false} : null;
            const sandbox = { [names.memo]:{c:()=>[]}, [names.host]:()=> 'host', [names.host_atom]:0,
              [names.auth]:()=>({authMethod:auth,isLoading:loading}), [names.query]:()=>({data,isPending:pending}),
              [names.query_key]:0, [names.converter]:x=>x };
            const start = patched.indexOf(`function ${names.ui}(e)`);
            const end = patched.indexOf(`var ${names.memo};`, start);
            assert(start >= 0 && end > start);
            const ui = vm.runInNewContext(patched.slice(start,end)+';'+names.ui, sandbox);
            const result = ui({hostId:'host'});
            assert.equal(result.isLoading, loading || pending);
            assert.equal(result.serviceTierAccess, loading || pending || !present ? null : data);
            checks++;
          }
        }
      }
    }
  }
  console.log(JSON.stringify({behavior_checks:checks,network_requests:0,passed:true}));
}
main().catch(e=>{console.error(e);process.exitCode=1});
