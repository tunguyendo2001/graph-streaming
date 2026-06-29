param(
  [int]$ControlsPerInsider = 2,
  [int]$RunSize = 50000,
  [string]$Python = "",
  [string]$MemgraphUri = "bolt://localhost:7687",
  [string]$CertRoot = "",
  [switch]$SkipPrepare,
  [switch]$SkipReplay,
  [switch]$NoDocker
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
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

if (-not $NoDocker) {
  Write-Host "[EVAL] Starting Memgraph Platform..."
  docker compose up -d
}

if (-not $SkipPrepare) {
  Write-Host "[EVAL] Preparing CERT r4.2 cohort stream..."
  & $Python "1_prepare_cert_data.py" `
    --input-dir $InputDir `
    --answers-dir $AnswersDir `
    --output "artifacts/evaluation_stream.jsonl" `
    --manifest "artifacts/cohort.json" `
    --controls-per-insider $ControlsPerInsider `
    --run-size $RunSize
}

if (-not $SkipReplay) {
  Write-Host "[EVAL] Replaying full stream into Memgraph..."
  & $Python "2_stream_cert.py" `
    --stream "artifacts/evaluation_stream.jsonl" `
    --uri $MemgraphUri `
    --reset `
    --delay 0 `
    --summary "artifacts/replay_summary.json"
}

Write-Host "[EVAL] Comparing graph motifs with flat rule baseline..."
& $Python "evaluation.py" `
  --answers-dir $AnswersDir `
  --stream "artifacts/evaluation_stream.jsonl" `
  --uri $MemgraphUri `
  --graph-output "artifacts/graph_metrics.json" `
  --rule-output "artifacts/rule_metrics.json" `
  --comparison-output "artifacts/comparison.json"

$Stopwatch.Stop()
$DockerStats = $null
try {
  $DockerStats = docker stats memgraph-platform --no-stream --format "{{json .}}" | ConvertFrom-Json
} catch {
  $DockerStats = @{ error = $_.Exception.Message }
}

$RunProfile = [ordered]@{
  elapsed_seconds = [Math]::Round($Stopwatch.Elapsed.TotalSeconds, 3)
  controls_per_insider = $ControlsPerInsider
  run_size = $RunSize
  stream = "artifacts/evaluation_stream.jsonl"
  replay_summary = "artifacts/replay_summary.json"
  graph_metrics = "artifacts/graph_metrics.json"
  rule_metrics = "artifacts/rule_metrics.json"
  comparison = "artifacts/comparison.json"
  memgraph_stats = $DockerStats
}

$RunProfile | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 "artifacts/run_profile.json"

Write-Host "[EVAL] Outputs: artifacts/graph_metrics.json, artifacts/rule_metrics.json, artifacts/comparison.json"
Write-Host "[EVAL] Run profile: artifacts/run_profile.json"
