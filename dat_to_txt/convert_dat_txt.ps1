param(
    [Parameter(Position = 0)]
    [ValidateSet('dat-to-txt', 'txt-to-dat')]
    [string]$Mode,

    [Parameter(Position = 1)]
    [string]$InputPath,

    [string]$OutputPath,

    [ValidateSet('auto', 'geoip', 'geosite')]
    [string]$Kind = 'auto'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-FullPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PathValue,

        [switch]$MustExist
    )

    if ($MustExist) {
        if (-not (Test-Path -LiteralPath $PathValue)) {
            throw "File not found: $PathValue"
        }

        return (Resolve-Path -LiteralPath $PathValue).Path
    }

    $resolved = Resolve-Path -LiteralPath $PathValue -ErrorAction SilentlyContinue
    if ($resolved) {
        return $resolved.Path
    }

    $parent = Split-Path -Parent $PathValue
    $leaf = Split-Path -Leaf $PathValue

    if ([string]::IsNullOrWhiteSpace($parent)) {
        $parent = (Get-Location).Path
    } elseif (-not (Test-Path -LiteralPath $parent)) {
        throw "Directory does not exist: $parent"
    } else {
        $parent = (Resolve-Path -LiteralPath $parent).Path
    }

    return (Join-Path $parent $leaf)
}

function Get-DefaultOutputPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$InputFullPath,

        [Parameter(Mandatory = $true)]
        [string]$ModeValue
    )

    $directory = Split-Path -Parent $InputFullPath
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($InputFullPath)
    if ([string]::IsNullOrWhiteSpace($baseName)) {
        $baseName = [System.IO.Path]::GetFileName($InputFullPath)
    }

    $newExtension = if ($ModeValue -eq 'dat-to-txt') { '.txt' } else { '.dat' }
    return (Join-Path $directory ($baseName + $newExtension))
}

function Get-KindHintFromPath {
    param([string]$PathValue)

    $name = [System.IO.Path]::GetFileNameWithoutExtension($PathValue).ToLowerInvariant()
    if ($name -match 'geoip') { return 'geoip' }
    if ($name -match 'geosite|geosit') { return 'geosite' }
    return $null
}

function Select-ModeInteractive {
    if (-not [Console]::IsInputRedirected) {
        Write-Host ''
        Write-Host 'Доступные режимы:'
        Write-Host '1. dat -> txt'
        Write-Host '2. txt -> dat'
    }

    while ($true) {
        $choice = (Read-Host 'Выберите режим, введя цифру').Trim()
        switch ($choice) {
            '1' { return 'dat-to-txt' }
            '2' { return 'txt-to-dat' }
            default {
                Write-Host 'Неверный выбор. Введите 1 или 2.'
            }
        }
    }
}

function Prompt-RequiredValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptText
    )

    while ($true) {
        $value = Read-Host $PromptText
        if (-not [string]::IsNullOrWhiteSpace($value)) {
            return $value.Trim()
        }

        Write-Host 'Значение не должно быть пустым.'
    }
}

function Prompt-OptionalValue {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PromptText
    )

    $value = Read-Host $PromptText
    if ([string]::IsNullOrWhiteSpace($value)) {
        return $null
    }

    return $value.Trim()
}

function Read-Varint {
    param([byte[]]$buf, [int]$i)

    [UInt64]$result = 0
    $shift = 0
    while ($true) {
        if ($i -ge $buf.Length) { throw 'truncated varint' }

        $b = $buf[$i]
        $i++
        $result = $result -bor ([UInt64]($b -band 0x7F) -shl $shift)

        if (($b -band 0x80) -eq 0) {
            return @($result, $i)
        }

        $shift += 7
        if ($shift -gt 64) { throw 'varint too long' }
    }
}

function Skip-Field {
    param([byte[]]$buf, [int]$i, [int]$wire)

    switch ($wire) {
        0 {
            $tmp = Read-Varint $buf $i
            return $tmp[1]
        }
        1 {
            return ($i + 8)
        }
        2 {
            $tmp = Read-Varint $buf $i
            $len = [int]$tmp[0]
            return ($tmp[1] + $len)
        }
        5 {
            return ($i + 4)
        }
        default {
            throw "unsupported wire type $wire"
        }
    }
}

function Parse-CIDR {
    param([byte[]]$msg)

    $i = 0
    $ipBytes = $null
    $prefix = $null

    while ($i -lt $msg.Length) {
        $tmp = Read-Varint $msg $i
        $tag = $tmp[0]
        $i = $tmp[1]
        $field = [int]($tag -shr 3)
        $wire = [int]($tag -band 7)

        if ($field -eq 1 -and $wire -eq 2) {
            $tmp = Read-Varint $msg $i
            $len = [int]$tmp[0]
            $i = $tmp[1]

            if ($len -gt 0) {
                $ipBytes = $msg[$i..($i + $len - 1)]
            } else {
                $ipBytes = @()
            }

            $i += $len
        } elseif ($field -eq 2 -and $wire -eq 0) {
            $tmp = Read-Varint $msg $i
            $prefix = [int]$tmp[0]
            $i = $tmp[1]
        } else {
            $i = Skip-Field $msg $i $wire
        }
    }

    if ($null -eq $ipBytes -or $null -eq $prefix) {
        return $null
    }

    try {
        $ip = [System.Net.IPAddress]::new($ipBytes)
        return '{0}/{1}' -f $ip.ToString(), $prefix
    } catch {
        return $null
    }
}

function Parse-GeoIP {
    param([byte[]]$msg)

    $i = 0
    $code = $null
    $inverse = $false
    $cidrs = New-Object 'System.Collections.Generic.List[string]'

    while ($i -lt $msg.Length) {
        $tmp = Read-Varint $msg $i
        $tag = $tmp[0]
        $i = $tmp[1]
        $field = [int]($tag -shr 3)
        $wire = [int]($tag -band 7)

        if ($field -eq 1 -and $wire -eq 2) {
            $tmp = Read-Varint $msg $i
            $len = [int]$tmp[0]
            $i = $tmp[1]
            $code = [Text.Encoding]::UTF8.GetString($msg, $i, $len)
            $i += $len
        } elseif ($field -eq 2 -and $wire -eq 2) {
            $tmp = Read-Varint $msg $i
            $len = [int]$tmp[0]
            $i = $tmp[1]
            $cidrMsg = $msg[$i..($i + $len - 1)]
            $i += $len
            $cidr = Parse-CIDR $cidrMsg
            if ($cidr) {
                $cidrs.Add($cidr) | Out-Null
            }
        } elseif ($field -eq 3 -and $wire -eq 0) {
            $tmp = Read-Varint $msg $i
            $inverse = [bool]$tmp[0]
            $i = $tmp[1]
        } else {
            $i = Skip-Field $msg $i $wire
        }
    }

    return [pscustomobject]@{
        Code = $code
        Cidrs = $cidrs
        Inverse = $inverse
    }
}

function Parse-GeoIPList {
    param([byte[]]$data)

    $i = 0
    $list = New-Object 'System.Collections.Generic.List[object]'

    while ($i -lt $data.Length) {
        $tmp = Read-Varint $data $i
        $tag = $tmp[0]
        $i = $tmp[1]
        $field = [int]($tag -shr 3)
        $wire = [int]($tag -band 7)

        if ($field -eq 1 -and $wire -eq 2) {
            $tmp = Read-Varint $data $i
            $len = [int]$tmp[0]
            $i = $tmp[1]
            $msg = $data[$i..($i + $len - 1)]
            $i += $len
            $list.Add((Parse-GeoIP $msg)) | Out-Null
        } else {
            $i = Skip-Field $data $i $wire
        }
    }

    return $list
}

function Parse-Domain {
    param([byte[]]$msg)

    $i = 0
    $domainType = 0
    $value = $null

    while ($i -lt $msg.Length) {
        $tmp = Read-Varint $msg $i
        $tag = $tmp[0]
        $i = $tmp[1]
        $field = [int]($tag -shr 3)
        $wire = [int]($tag -band 7)

        if ($field -eq 1 -and $wire -eq 0) {
            $tmp = Read-Varint $msg $i
            $domainType = [int]$tmp[0]
            $i = $tmp[1]
        } elseif ($field -eq 2 -and $wire -eq 2) {
            $tmp = Read-Varint $msg $i
            $len = [int]$tmp[0]
            $i = $tmp[1]
            $value = [Text.Encoding]::UTF8.GetString($msg, $i, $len)
            $i += $len
        } else {
            $i = Skip-Field $msg $i $wire
        }
    }

    return [pscustomobject]@{
        Type = $domainType
        Value = $value
    }
}

function Parse-GeoSite {
    param([byte[]]$msg)

    $i = 0
    $code = $null
    $domains = New-Object 'System.Collections.Generic.List[object]'

    while ($i -lt $msg.Length) {
        $tmp = Read-Varint $msg $i
        $tag = $tmp[0]
        $i = $tmp[1]
        $field = [int]($tag -shr 3)
        $wire = [int]($tag -band 7)

        if ($field -eq 1 -and $wire -eq 2) {
            $tmp = Read-Varint $msg $i
            $len = [int]$tmp[0]
            $i = $tmp[1]
            $code = [Text.Encoding]::UTF8.GetString($msg, $i, $len)
            $i += $len
        } elseif ($field -eq 2 -and $wire -eq 2) {
            $tmp = Read-Varint $msg $i
            $len = [int]$tmp[0]
            $i = $tmp[1]
            $domainMsg = $msg[$i..($i + $len - 1)]
            $i += $len
            $domains.Add((Parse-Domain $domainMsg)) | Out-Null
        } else {
            $i = Skip-Field $msg $i $wire
        }
    }

    return [pscustomobject]@{
        Code = $code
        Domains = $domains
    }
}

function Parse-GeoSiteList {
    param([byte[]]$data)

    $i = 0
    $list = New-Object 'System.Collections.Generic.List[object]'

    while ($i -lt $data.Length) {
        $tmp = Read-Varint $data $i
        $tag = $tmp[0]
        $i = $tmp[1]
        $field = [int]($tag -shr 3)
        $wire = [int]($tag -band 7)

        if ($field -eq 1 -and $wire -eq 2) {
            $tmp = Read-Varint $data $i
            $len = [int]$tmp[0]
            $i = $tmp[1]
            $msg = $data[$i..($i + $len - 1)]
            $i += $len
            $list.Add((Parse-GeoSite $msg)) | Out-Null
        } else {
            $i = Skip-Field $data $i $wire
        }
    }

    return $list
}

function Write-Varint {
    param([System.IO.Stream]$ms, [UInt64]$value)

    while ($value -ge 0x80) {
        $byteValue = [byte](($value -band 0x7F) -bor 0x80)
        $ms.WriteByte($byteValue)
        $value = $value -shr 7
    }

    $ms.WriteByte([byte]$value)
}

function Write-Tag {
    param([System.IO.Stream]$ms, [int]$field, [int]$wire)

    $tag = [UInt64](($field -shl 3) -bor $wire)
    Write-Varint $ms $tag
}

function Write-BytesField {
    param([System.IO.Stream]$ms, [int]$field, [byte[]]$bytes)

    Write-Tag $ms $field 2
    Write-Varint $ms ([UInt64]$bytes.Length)
    if ($bytes.Length -gt 0) {
        $ms.Write($bytes, 0, $bytes.Length)
    }
}

function Write-StringField {
    param([System.IO.Stream]$ms, [int]$field, [string]$text)

    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    Write-BytesField $ms $field $bytes
}

function Write-UIntField {
    param([System.IO.Stream]$ms, [int]$field, [UInt64]$value)

    Write-Tag $ms $field 0
    Write-Varint $ms $value
}

function Encode-CIDR {
    param([string]$cidr)

    $parts = $cidr.Split('/')
    if ($parts.Count -ne 2) {
        throw "Invalid CIDR: $cidr"
    }

    $ipString = $parts[0].Trim()
    $prefix = [int]$parts[1].Trim()
    $ip = [System.Net.IPAddress]::Parse($ipString)
    $ipBytes = $ip.GetAddressBytes()

    $ms = New-Object System.IO.MemoryStream
    Write-BytesField $ms 1 $ipBytes
    Write-UIntField $ms 2 ([UInt64]$prefix)
    return $ms.ToArray()
}

function Encode-GeoIP {
    param(
        [string]$code,
        [System.Collections.Generic.List[string]]$cidrs,
        [bool]$inverse
    )

    $ms = New-Object System.IO.MemoryStream
    Write-StringField $ms 1 $code
    foreach ($cidr in $cidrs) {
        $cidrBytes = Encode-CIDR $cidr
        Write-BytesField $ms 2 $cidrBytes
    }

    if ($inverse) {
        Write-UIntField $ms 3 1
    }

    return $ms.ToArray()
}

function Encode-GeoIPList {
    param($entries)

    $ms = New-Object System.IO.MemoryStream
    foreach ($entry in $entries) {
        $msg = Encode-GeoIP $entry.Code $entry.Cidrs $entry.Inverse
        Write-BytesField $ms 1 $msg
    }

    return $ms.ToArray()
}

function Encode-Domain {
    param([int]$type, [string]$value)

    $ms = New-Object System.IO.MemoryStream
    Write-UIntField $ms 1 ([UInt64]$type)
    Write-StringField $ms 2 $value
    return $ms.ToArray()
}

function Encode-GeoSite {
    param([string]$code, $domains)

    $ms = New-Object System.IO.MemoryStream
    Write-StringField $ms 1 $code
    foreach ($domain in $domains) {
        $domainMsg = Encode-Domain $domain.Type $domain.Value
        Write-BytesField $ms 2 $domainMsg
    }

    return $ms.ToArray()
}

function Encode-GeoSiteList {
    param($entries)

    $ms = New-Object System.IO.MemoryStream
    foreach ($entry in $entries) {
        $msg = Encode-GeoSite $entry.Code $entry.Domains
        Write-BytesField $ms 1 $msg
    }

    return $ms.ToArray()
}

function Test-ValidCidr {
    param([string]$Cidr)

    try {
        $parts = $Cidr.Split('/')
        if ($parts.Count -ne 2) { return $false }

        $ip = [System.Net.IPAddress]::Parse($parts[0].Trim())
        $prefix = [int]$parts[1].Trim()
        $maxPrefix = if ($ip.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) { 32 } else { 128 }
        return ($prefix -ge 0 -and $prefix -le $maxPrefix)
    } catch {
        return $false
    }
}

function Test-GeoIPEntries {
    param($Entries)

    if ($null -eq $Entries -or $Entries.Count -eq 0) {
        return $false
    }

    $cidrCount = 0
    foreach ($entry in $Entries) {
        if ([string]::IsNullOrWhiteSpace($entry.Code)) {
            return $false
        }

        if ($null -eq $entry.Cidrs) {
            return $false
        }

        foreach ($cidr in $entry.Cidrs) {
            if (-not (Test-ValidCidr $cidr)) {
                return $false
            }

            $cidrCount++
        }
    }

    return ($cidrCount -gt 0)
}

function Test-GeoSiteEntries {
    param($Entries)

    if ($null -eq $Entries -or $Entries.Count -eq 0) {
        return $false
    }

    $domainCount = 0
    foreach ($entry in $Entries) {
        if ([string]::IsNullOrWhiteSpace($entry.Code)) {
            return $false
        }

        if ($null -eq $entry.Domains) {
            return $false
        }

        foreach ($domain in $entry.Domains) {
            if ([string]::IsNullOrWhiteSpace($domain.Value)) {
                return $false
            }

            if ($domain.Type -lt 0) {
                return $false
            }

            $domainCount++
        }
    }

    return ($domainCount -gt 0)
}

function Convert-GeoIPEntriesToText {
    param($Entries)

    $builder = New-Object System.Text.StringBuilder
    foreach ($entry in $Entries) {
        $inverseText = if ($entry.Inverse) { ' (inverse)' } else { '' }
        $null = $builder.AppendLine("[$($entry.Code)]$inverseText")
        foreach ($cidr in $entry.Cidrs) {
            $null = $builder.AppendLine($cidr)
        }
        $null = $builder.AppendLine('')
    }

    return $builder.ToString()
}

function Convert-GeoSiteEntriesToText {
    param($Entries)

    $typeMap = @{
        0 = 'plain'
        1 = 'regex'
        2 = 'domain'
        3 = 'full'
    }

    $builder = New-Object System.Text.StringBuilder
    foreach ($entry in $Entries) {
        $null = $builder.AppendLine("[$($entry.Code)]")
        foreach ($domain in $entry.Domains) {
            $typeLabel = if ($typeMap.ContainsKey($domain.Type)) { $typeMap[$domain.Type] } else { [string]$domain.Type }
            $null = $builder.AppendLine("${typeLabel}:$($domain.Value)")
        }
        $null = $builder.AppendLine('')
    }

    return $builder.ToString()
}

function Parse-GeoIPText {
    param([string[]]$Lines)

    $entries = New-Object 'System.Collections.Generic.List[object]'
    $current = $null

    foreach ($raw in $Lines) {
        $line = $raw.Trim()
        if (-not $line) { continue }
        if ($line.StartsWith('#') -or $line.StartsWith('//')) { continue }

        if ($line -match '^\[(.+?)\]\s*(?:\((?i:inverse)\))?\s*$') {
            if ($current) {
                $entries.Add($current) | Out-Null
            }

            $code = $Matches[1]
            $inverse = ($line -match '(?i:inverse)')
            $current = [pscustomobject]@{
                Code = $code
                Cidrs = New-Object 'System.Collections.Generic.List[string]'
                Inverse = $inverse
            }
            continue
        }

        if (-not $current) {
            throw "CIDR without group header: $line"
        }

        if (-not (Test-ValidCidr $line)) {
            throw "Invalid CIDR: $line"
        }

        $current.Cidrs.Add($line) | Out-Null
    }

    if ($current) {
        $entries.Add($current) | Out-Null
    }

    if (-not (Test-GeoIPEntries $entries)) {
        throw 'Input text is not a valid geoip list'
    }

    return $entries
}

function Parse-GeoSiteText {
    param([string[]]$Lines)

    $typeToInt = @{
        plain = 0
        regex = 1
        domain = 2
        full = 3
    }

    $entries = New-Object 'System.Collections.Generic.List[object]'
    $current = $null

    foreach ($raw in $Lines) {
        $line = $raw.Trim()
        if (-not $line) { continue }
        if ($line.StartsWith('#') -or $line.StartsWith('//')) { continue }

        if ($line -match '^\[(.+?)\]\s*$') {
            if ($current) {
                $entries.Add($current) | Out-Null
            }

            $current = [pscustomobject]@{
                Code = $Matches[1]
                Domains = New-Object 'System.Collections.Generic.List[object]'
            }
            continue
        }

        if (-not $current) {
            throw "Domain without group header: $line"
        }

        $separatorIndex = $line.IndexOf(':')
        if ($separatorIndex -lt 0) {
            throw "Invalid domain line (expected type:value): $line"
        }

        $typeString = $line.Substring(0, $separatorIndex).Trim().ToLowerInvariant()
        $value = $line.Substring($separatorIndex + 1).Trim()

        if (-not $value) {
            continue
        }

        if ($typeToInt.ContainsKey($typeString)) {
            $typeValue = $typeToInt[$typeString]
        } elseif ($typeString -match '^\d+$') {
            $typeValue = [int]$typeString
        } else {
            throw "Unknown domain type: $typeString"
        }

        $current.Domains.Add([pscustomobject]@{
            Type = $typeValue
            Value = $value
        }) | Out-Null
    }

    if ($current) {
        $entries.Add($current) | Out-Null
    }

    if (-not (Test-GeoSiteEntries $entries)) {
        throw 'Input text is not a valid geosite list'
    }

    return $entries
}

function Get-ParseOrder {
    param(
        [string]$RequestedKind,
        [string]$PathHint,
        [string[]]$FallbackKinds
    )

    $order = New-Object 'System.Collections.Generic.List[string]'

    if ($RequestedKind -and $RequestedKind -ne 'auto') {
        $order.Add($RequestedKind) | Out-Null
    }

    if ($RequestedKind -eq 'auto' -and $PathHint) {
        $order.Add($PathHint) | Out-Null
    }

    foreach ($kindItem in $FallbackKinds) {
        if (-not $order.Contains($kindItem)) {
            $order.Add($kindItem) | Out-Null
        }
    }

    return $order
}

function Detect-DatKindAndParse {
    param(
        [byte[]]$Data,
        [string]$RequestedKind,
        [string]$InputFullPath
    )

    $pathHint = Get-KindHintFromPath $InputFullPath
    $order = Get-ParseOrder $RequestedKind $pathHint @('geoip', 'geosite')

    foreach ($kindItem in $order) {
        try {
            if ($kindItem -eq 'geoip') {
                $entries = Parse-GeoIPList $Data
                if (Test-GeoIPEntries $entries) {
                    return [pscustomobject]@{ Kind = 'geoip'; Entries = $entries }
                }
            } else {
                $entries = Parse-GeoSiteList $Data
                if (Test-GeoSiteEntries $entries) {
                    return [pscustomobject]@{ Kind = 'geosite'; Entries = $entries }
                }
            }
        } catch {
        }
    }

    throw "Unable to detect dat format for: $InputFullPath"
}

function Detect-TextKindAndParse {
    param(
        [string[]]$Lines,
        [string]$RequestedKind,
        [string]$InputFullPath
    )

    $pathHint = Get-KindHintFromPath $InputFullPath
    $order = Get-ParseOrder $RequestedKind $pathHint @('geoip', 'geosite')

    foreach ($kindItem in $order) {
        try {
            if ($kindItem -eq 'geoip') {
                $entries = Parse-GeoIPText $Lines
                return [pscustomobject]@{ Kind = 'geoip'; Entries = $entries }
            }

            $entries = Parse-GeoSiteText $Lines
            return [pscustomobject]@{ Kind = 'geosite'; Entries = $entries }
        } catch {
        }
    }

    throw "Unable to detect text format for: $InputFullPath"
}

$interactiveMode = $false

if ([string]::IsNullOrWhiteSpace($Mode)) {
    $interactiveMode = $true
    $Mode = Select-ModeInteractive
}

if ([string]::IsNullOrWhiteSpace($InputPath)) {
    $interactiveMode = $true
    $sourceLabel = if ($Mode -eq 'dat-to-txt') { '.dat' } else { '.txt' }
    $InputPath = Prompt-RequiredValue "Введите путь к входному файлу $sourceLabel"
}

$inputFullPath = Resolve-FullPath -PathValue $InputPath -MustExist
$defaultOutputPath = Get-DefaultOutputPath -InputFullPath $inputFullPath -ModeValue $Mode

if ($interactiveMode -and -not $PSBoundParameters.ContainsKey('OutputPath')) {
    $promptText = "Введите путь для выходного файла или нажмите Enter для значения по умолчанию [$defaultOutputPath]"
    $OutputPath = Prompt-OptionalValue $promptText
}

$outputFullPath = if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $defaultOutputPath
} else {
    Resolve-FullPath -PathValue $OutputPath
}

if ($inputFullPath.Equals($outputFullPath, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Input and output paths must be different'
}

if ($Mode -eq 'dat-to-txt') {
    $data = [System.IO.File]::ReadAllBytes($inputFullPath)
    $parsed = Detect-DatKindAndParse -Data $data -RequestedKind $Kind -InputFullPath $inputFullPath

    $text = if ($parsed.Kind -eq 'geoip') {
        Convert-GeoIPEntriesToText $parsed.Entries
    } else {
        Convert-GeoSiteEntriesToText $parsed.Entries
    }

    [System.IO.File]::WriteAllText($outputFullPath, $text, [Text.Encoding]::UTF8)
    Write-Output "Converted $($parsed.Kind) dat -> txt"
    Write-Output "Input : $inputFullPath"
    Write-Output "Output: $outputFullPath"
    exit 0
}

$lines = [System.IO.File]::ReadAllLines($inputFullPath)
$parsed = Detect-TextKindAndParse -Lines $lines -RequestedKind $Kind -InputFullPath $inputFullPath
$bytes = if ($parsed.Kind -eq 'geoip') {
    Encode-GeoIPList $parsed.Entries
} else {
    Encode-GeoSiteList $parsed.Entries
}

[System.IO.File]::WriteAllBytes($outputFullPath, $bytes)
Write-Output "Converted $($parsed.Kind) txt -> dat"
Write-Output "Input : $inputFullPath"
Write-Output "Output: $outputFullPath"
