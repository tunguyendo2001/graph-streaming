param(
  [int]$ControlsPerInsider = 1,
  [int]$RunSize = 10000,
  [int]$Limit = 5000,
  [string]$Python = "",
  [string]$MemgraphUri = "bolt://localhost:7687",
  [string]$CertRoot = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

if ([string]::IsNullOrWhiteSpace($Python)) {
  $Python = if ($env:PYTHON) { $env:PYTHON } else { "python" }
}
if ([string]::IsNullOrWhiteSpace($CertRoot)) {
  $Candidates = @(
    (Join-Path $RepoRoot "data\cert-r4.2"),
    (Join-Path $RepoRoot "..\..\data\cert-r4.2")
  )
  foreach ($Candidate in $Candidates) {
    if (Test-Path (Join-Path $Candidate "answers\insiders.csv")) {
      $CertRoot = (Resolve-Path $Candidate).Path
      break
    }
  }
}
if ([string]::IsNullOrWhiteSpace($CertRoot)) {
  throw "Cannot find data\cert-r4.2. Pass -CertRoot explicitly."
}
$InputDir = Join-Path $CertRoot "r4.2"
$AnswersDir = Join-Path $CertRoot "answers"

New-Item -ItemType Directory -Force -Path "artifacts" | Out-Null

Write-Host "[DEMO] Starting Memgraph Platform..."
docker compose up -d

Write-Host "[DEMO] Preparing bounded CERT r4.2 stream..."
& $Python "1_prepare_cert_data.py" `
  --input-dir $InputDir `
  --answers-dir $AnswersDir `
  --output "artifacts/evaluation_stream.jsonl" `
  --manifest "artifacts/cohort.json" `
  --controls-per-insider $ControlsPerInsider `
  --run-size $RunSize

Write-Host "[DEMO] Replaying first $Limit events into Memgraph..."
& $Python "2_stream_cert.py" `
  --stream "artifacts/evaluation_stream.jsonl" `
  --uri $MemgraphUri `
  --reset `
  --delay 0 `
  --limit $Limit `
  --summary "artifacts/replay_summary.json"

Write-Host "[DEMO] Evaluating graph alerts vs flat rule baseline..."
& $Python "evaluation.py" `
  --answers-dir $AnswersDir `
  --stream "artifacts/evaluation_stream.jsonl" `
  --uri $MemgraphUri `
  --graph-output "artifacts/graph_metrics.json" `
  --rule-output "artifacts/rule_metrics.json" `
  --comparison-output "artifacts/comparison.json"

Write-Host "[DEMO] Memgraph Lab: http://localhost:3000"
Write-Host "[DEMO] Outputs: artifacts/replay_summary.json, artifacts/graph_metrics.json, artifacts/rule_metrics.json, artifacts/comparison.json"
