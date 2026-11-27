param(
    [string]$ConnectionString = "Server=localhost;Database=Spunk;Integrated Security=True;TrustServerCertificate=True",
    [string]$PublishDir = "C:\Spunk",
    [int]$Port = 514
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    if (Test-Path "$root\web\package.json") {
        Push-Location "$root\web"
        npm ci
        npm run build
        Pop-Location
    }
    dotnet publish "$root\src\Spunk.Api\Spunk.Api.csproj" -c Release -o $PublishDir
    $exe = Join-Path $PublishDir "Spunk.Api.exe"
    $settings = Join-Path $PublishDir "appsettings.json"
    if (Test-Path $settings) {
        $json = Get-Content $settings -Raw | ConvertFrom-Json
        $json.ConnectionStrings.SqlServer = $ConnectionString
        $json.Ingest.UdpPort = $Port
        $json.Ingest.TcpPort = $Port
        $json | ConvertTo-Json -Depth 8 | Set-Content $settings
    }
    if (Get-Service -Name Spunk -ErrorAction SilentlyContinue) {
        Stop-Service Spunk -Force
        sc.exe delete Spunk | Out-Null
        Start-Sleep -Seconds 1
    }
    New-Service -Name Spunk -BinaryPathName $exe -DisplayName "Spunk Log Analytics" -StartupType Automatic | Out-Null
    Start-Service Spunk
    Write-Host "Spunk is running as a Windows service. UI: http://localhost:8080"
}
finally {
    Pop-Location
}
