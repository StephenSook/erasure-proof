// Erasure Proof Verifier: an auditor's pocket tool. Import a signed erasure certificate (the JSON
// the web app's "Download the signed proof" produces) and verify the ECDSA P-256 signature and
// tamper-evidence ENTIRELY on this device, with no server and no network. What the verdict covers
// (the exact signed bytes) is what the screen shows.

import { StatusBar } from 'expo-status-bar'
import { useState } from 'react'
import {
  Platform,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native'
import demoProof from './assets/demo-proof.json'
import { type ProofFile, verifyProof, type VerifyResult } from './src/verify'

const MONO = Platform.OS === 'ios' ? 'Menlo' : 'monospace'

const C = {
  bg: '#1c1b1a',
  panel: '#242322',
  panel2: '#151413',
  line: '#3a3733',
  fg0: '#f6f4f2',
  fg1: '#d8d4ce',
  fg2: '#a29c94',
  fg3: '#6e6860',
  turq: '#00ffaa',
  red: '#ff4b4b',
  green: '#8dff55',
  warn: '#ffcc2a',
}

// The signed facts worth showing, in order, with human labels. Keys map to the canonical proof.
const FACT_ROWS: { key: string; label: string }[] = [
  { key: 'subject_hash', label: 'subject (SHA-256)' },
  { key: 'decision_log_seq', label: 'decision-log seq' },
  { key: 'occurred_at', label: 'erased at' },
  { key: 'kms_key_state', label: 'KMS key state' },
  { key: 'wrapped_key_fingerprint', label: 'wrapped-key fingerprint' },
  { key: 'merkle_root', label: 'transparency root' },
  { key: 'tree_size', label: 'tree size' },
]

function short(v: unknown, n = 28): string {
  const s = String(v ?? '')
  return s.length > n ? s.slice(0, n) + '...' : s
}

export default function App() {
  const [pasted, setPasted] = useState('')
  const [result, setResult] = useState<VerifyResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const runVerify = (file: ProofFile) => {
    setError(null)
    setResult(verifyProof(file))
  }

  const onVerifyPasted = () => {
    setResult(null)
    if (!pasted.trim()) {
      setError('Paste a proof JSON, or load the demo certificate.')
      return
    }
    let parsed: ProofFile
    try {
      parsed = JSON.parse(pasted) as ProofFile
    } catch {
      setError('That is not valid JSON. Paste the downloaded proof file verbatim.')
      return
    }
    runVerify(parsed)
  }

  const onLoadDemo = () => {
    setPasted(JSON.stringify(demoProof, null, 2))
    runVerify(demoProof as ProofFile)
  }

  const onClear = () => {
    setPasted('')
    setResult(null)
    setError(null)
  }

  return (
    <View style={styles.root}>
      <StatusBar style="light" />
      <ScrollView contentContainerStyle={styles.scroll} keyboardShouldPersistTaps="handled">
        <View style={styles.header}>
          <Text style={styles.brand}>
            erasure<Text style={{ color: C.turq }}>-proof</Text>
          </Text>
          <View style={styles.offlinePill}>
            <View style={styles.dot} />
            <Text style={styles.offlineText}>runs offline</Text>
          </View>
        </View>

        <Text style={styles.title}>ERASURE PROOF VERIFIER</Text>
        <Text style={styles.lead}>
          Import a signed erasure certificate. This device verifies the ECDSA signature and its
          tamper-evidence with no server and no network. Turn on airplane mode and it still works.
        </Text>

        <View style={styles.actions}>
          <Pressable style={[styles.btn, styles.btnAccent]} onPress={onLoadDemo}>
            <Text style={styles.btnAccentText}>Load demo certificate</Text>
          </Pressable>
          <Pressable style={styles.btn} onPress={onClear}>
            <Text style={styles.btnText}>Clear</Text>
          </Pressable>
        </View>

        <Text style={styles.fieldLabel}>Or paste a downloaded proof JSON</Text>
        <TextInput
          style={styles.input}
          value={pasted}
          onChangeText={setPasted}
          placeholder='{ "proof_canonical": "...", "signature_b64": "...", "signer_public_key_pem": "..." }'
          placeholderTextColor={C.fg3}
          multiline
          autoCapitalize="none"
          autoCorrect={false}
        />
        <Pressable style={[styles.btn, styles.btnAccent, styles.verifyBtn]} onPress={onVerifyPasted}>
          <Text style={styles.btnAccentText}>Verify on this device</Text>
        </Pressable>

        {error && <Text style={styles.error}>{error}</Text>}

        {result && result.kind === 'malformed' && (
          <View style={[styles.verdictCard, { borderColor: C.warn }]}>
            <Text style={[styles.verdict, { color: C.warn }]}>MALFORMED PROOF</Text>
            <Text style={styles.verdictNote}>{result.message}</Text>
          </View>
        )}

        {result && result.kind === 'invalid' && (
          <View style={[styles.verdictCard, { borderColor: C.red }]}>
            <Text style={[styles.verdict, { color: C.red }]}>SIGNATURE INVALID</Text>
            <Text style={styles.verdictNote}>
              The signature does not verify over these bytes. The certificate was altered, or the
              signature and key do not match it.
            </Text>
          </View>
        )}

        {result && result.kind === 'verified' && (
          <View style={[styles.verdictCard, { borderColor: C.green }]}>
            <Text style={[styles.verdict, { color: C.green }]}>SIGNATURE VERIFIED</Text>
            <Text style={styles.verdictNote}>
              ECDSA P-256 over the exact signed bytes, checked on this device. These facts are read
              from the signed bytes, so what is verified is what you see.
            </Text>
            <View style={styles.facts}>
              {FACT_ROWS.map(
                (row) =>
                  result.facts[row.key] !== undefined && (
                    <View style={styles.factRow} key={row.key}>
                      <Text style={styles.factKey}>{row.label}</Text>
                      <Text style={styles.factVal}>{short(result.facts[row.key])}</Text>
                    </View>
                  ),
              )}
              <View style={styles.factRow}>
                <Text style={styles.factKey}>signer key fingerprint</Text>
                <Text style={styles.factVal}>{result.signerFingerprint}</Text>
              </View>
            </View>
            {typeof result.facts.nist_condition === 'string' && (
              <Text style={styles.nist}>{result.facts.nist_condition}</Text>
            )}
          </View>
        )}

        <Text style={styles.footer}>
          The ECDSA signature and tamper-check run entirely offline on this device. The S3 Object
          Lock anchor and the full RFC 6962 inclusion proof are online cross-checks in the web app.
          Crypto: @noble/curves P-256, pure JavaScript, no native module.
        </Text>
      </ScrollView>
    </View>
  )
}

const styles = StyleSheet.create({
  root: { flex: 1, backgroundColor: C.bg },
  scroll: { padding: 20, paddingTop: 64, paddingBottom: 48 },
  header: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center' },
  brand: { color: C.fg0, fontWeight: '700', fontSize: 18, letterSpacing: 0.5 },
  offlinePill: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 6,
    borderWidth: 1,
    borderColor: C.line,
    borderRadius: 999,
    paddingHorizontal: 10,
    paddingVertical: 4,
  },
  dot: { width: 8, height: 8, borderRadius: 4, backgroundColor: C.green },
  offlineText: { color: C.fg2, fontSize: 11, textTransform: 'uppercase', letterSpacing: 1 },
  title: {
    color: C.fg0,
    fontSize: 30,
    fontWeight: '800',
    letterSpacing: 1,
    marginTop: 28,
  },
  lead: { color: C.fg2, fontSize: 14, lineHeight: 21, marginTop: 12 },
  actions: { flexDirection: 'row', gap: 10, marginTop: 24 },
  btn: {
    borderWidth: 1,
    borderColor: C.line,
    borderRadius: 8,
    paddingVertical: 12,
    paddingHorizontal: 16,
    backgroundColor: C.panel,
  },
  btnText: { color: C.fg0, fontSize: 14, fontWeight: '600' },
  btnAccent: { backgroundColor: C.turq, borderColor: C.turq },
  btnAccentText: { color: C.bg, fontSize: 14, fontWeight: '700' },
  fieldLabel: { color: C.fg3, fontSize: 12, marginTop: 24, marginBottom: 8, letterSpacing: 0.5 },
  input: {
    borderWidth: 1,
    borderColor: C.line,
    borderRadius: 8,
    backgroundColor: C.panel2,
    color: C.fg1,
    fontFamily: MONO,
    fontSize: 11,
    minHeight: 120,
    padding: 12,
    textAlignVertical: 'top',
  },
  verifyBtn: { marginTop: 12, alignItems: 'center' },
  error: { color: C.red, fontSize: 13, marginTop: 14 },
  verdictCard: {
    marginTop: 22,
    borderWidth: 1,
    borderRadius: 12,
    padding: 18,
    backgroundColor: C.panel,
  },
  verdict: { fontSize: 22, fontWeight: '800', letterSpacing: 1 },
  verdictNote: { color: C.fg2, fontSize: 13, lineHeight: 20, marginTop: 8 },
  facts: { marginTop: 16, borderTopWidth: 1, borderTopColor: C.line, paddingTop: 12, gap: 8 },
  factRow: { flexDirection: 'row', justifyContent: 'space-between', gap: 12 },
  factKey: { color: C.fg3, fontSize: 12, flexShrink: 0 },
  factVal: { color: C.fg0, fontSize: 12, fontFamily: MONO, flexShrink: 1, textAlign: 'right' },
  nist: {
    color: C.fg2,
    fontSize: 11,
    lineHeight: 17,
    marginTop: 14,
    fontStyle: 'italic',
  },
  footer: { color: C.fg3, fontSize: 11, lineHeight: 17, marginTop: 28 },
})
