param(
    [ValidateSet('check','prepare','rehearse','ssh','alert','policy','scheduled','scope','extended','finish')]
    [string]$Step = 'check'
)
$ErrorActionPreference = 'Stop'
$demoPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
$demoScript = Join-Path $PSScriptRoot 'scripts\demo.py'
if (-not (Test-Path -LiteralPath $demoPython)) {
    throw 'Create the project virtual environment and install requirements.txt first (see README).'
}
if ($Step -in @('ssh','alert','policy','scheduled','scope','extended')) {
    & $demoPython $demoScript step $Step
} else {
    & $demoPython $demoScript $Step
}
if ($LASTEXITCODE -ne 0) {
    throw 'The demo step did not pass. Read the error above before continuing.'
}
