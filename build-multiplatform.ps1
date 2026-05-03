$ErrorActionPreference = "Stop"

$ProjectRoot = "e:\Development\Src\Go\CorazaWafProxy\CorazaWafProxy0.3.3"
$OutputDir = "$ProjectRoot\build"
Set-Location $ProjectRoot

$Platforms = @(
    @{GOOS="windows"; GOARCH="amd64"; Folder="windows-amd64"; Ext=".exe"},
    @{GOOS="windows"; GOARCH="arm64"; Folder="windows-arm64"; Ext=".exe"},
    @{GOOS="linux"; GOARCH="amd64"; Folder="linux-amd64"; Ext=""},
    @{GOOS="linux"; GOARCH="arm64"; Folder="linux-arm64"; Ext=""}
)

if (Test-Path $OutputDir) {
    Remove-Item $OutputDir -Recurse -Force
}
New-Item $OutputDir -ItemType Directory | Out-Null

$Resources = @("config", "coreruleset", "static", "web", "install.sh")

Write-Host "开始编译多平台版本..." -ForegroundColor Cyan

foreach ($Platform in $Platforms) {
    $GOOS = $Platform.GOOS
    $GOARCH = $Platform.GOARCH
    $Folder = $Platform.Folder
    $Ext = $Platform.Ext
    $BinaryName = "coraza-waf-proxy-$Folder$Ext"

    Write-Host "`n========== 编译 $Folder ==========" -ForegroundColor Yellow

    $Env:GOOS = $GOOS
    $Env:GOARCH = $GOARCH

    Write-Host "正在编译 $BinaryName..."
    go build -o "$OutputDir\$Folder\$BinaryName" .

    if ($LASTEXITCODE -ne 0) {
        Write-Host "编译 $Folder 失败!" -ForegroundColor Red
        exit 1
    }

    Write-Host "正在复制资源文件..."
    foreach ($Resource in $Resources) {
        if ($Resource -eq "install.sh") {
            $SourceFile = "$ProjectRoot\$Resource"
            $DestFile = "$OutputDir\$Folder\$Resource"
            if (Test-Path $SourceFile) {
                Copy-Item $SourceFile $DestFile -Force
                Write-Host "  复制 $Resource -> build\$Folder/"
            }
        } else {
            $SourcePath = "$ProjectRoot\$Resource"
            $DestPath = "$OutputDir\$Folder\$Resource"
            if (Test-Path $SourcePath) {
                if (Test-Path $DestPath) {
                    Remove-Item $DestPath -Recurse -Force
                }
                Copy-Item $SourcePath $DestPath -Recurse -Force
                Write-Host "  复制 $Resource -> build\$Folder/"
            }
        }
    }

    Write-Host "$Folder 编译完成!" -ForegroundColor Green
}

$Env:GOOS = $null
$Env:GOARCH = $null

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "所有平台编译完成!" -ForegroundColor Cyan
Write-Host ""

foreach ($Platform in $Platforms) {
    $Folder = $Platform.Folder
    $BinaryName = "coraza-waf-proxy-$Folder$($Platform.Ext)"
    $BinaryPath = "$OutputDir\$Folder\$BinaryName"
    if (Test-Path $BinaryPath) {
        $Size = (Get-Item $BinaryPath).Length / 1MB
        Write-Host "  $Folder : $BinaryName ($([math]::Round($Size, 2)) MB)"
    }
}
