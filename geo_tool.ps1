param(
    [Parameter(Mandatory = $false, Position = 0)]
    [ValidateSet('export', 'import', 'help')]
    [string]$Mode = 'help',

    [string]$GeoIpDat = 'geoip.dat',
    [string]$GeoSiteDat = 'geosite.dat',
    [string]$GeoIpTxt = 'geoip_list.txt',
    [string]$GeoSiteTxt = 'geosite_list.txt'
)

function Resolve-PathIfMissing {
    param([string]$PathValue, [string[]]$Candidates)
    if (Test-Path $PathValue) { return $PathValue }
    foreach ($c in $Candidates) {
        if (Test-Path $c) { return $c }
    }
    return $PathValue
}

function Resolve-OutputPath {
    param([string]$PathValue, [string[]]$Candidates)
    if (Test-Path $PathValue) { return $PathValue }
    foreach ($c in $Candidates) {
        $dir = Split-Path -Parent $c
        if (-not $dir) { continue }
        if (Test-Path $dir) { return $c }
    }
    return $PathValue
}

$editsGeoIp = Join-Path 'edits' 'geoip_list.txt'
$editsGeoSite = Join-Path 'edits' 'geosite_list.txt'
$completeGeoIp = Join-Path 'complete' 'geoip.dat'
$completeGeoSite = Join-Path 'complete' 'geosite.dat'

if (-not $PSBoundParameters.ContainsKey('GeoIpTxt')) {
    $GeoIpTxt = Resolve-PathIfMissing $GeoIpTxt @($editsGeoIp)
}
if (-not $PSBoundParameters.ContainsKey('GeoSiteTxt')) {
    $GeoSiteTxt = Resolve-PathIfMissing $GeoSiteTxt @($editsGeoSite)
}
if (-not $PSBoundParameters.ContainsKey('GeoIpDat')) {
    $GeoIpDat = Resolve-OutputPath $GeoIpDat @($completeGeoIp)
}
if (-not $PSBoundParameters.ContainsKey('GeoSiteDat')) {
    $GeoSiteDat = Resolve-OutputPath $GeoSiteDat @($completeGeoSite)
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
        if (($b -band 0x80) -eq 0) { return @($result, $i) }
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
        1 { return $i + 8 }
        2 {
            $tmp = Read-Varint $buf $i
            $len = [int]$tmp[0]
            return $tmp[1] + $len
        }
        5 { return $i + 4 }
        default { throw "unsupported wire type $wire" }
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
    if ($null -eq $ipBytes -or $null -eq $prefix) { return $null }
    try {
        $ip = [System.Net.IPAddress]::new($ipBytes)
        return "{0}/{1}" -f $ip.ToString(), $prefix
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
            if ($cidr) { $cidrs.Add($cidr) }
        } elseif ($field -eq 3 -and $wire -eq 0) {
            $tmp = Read-Varint $msg $i
            $inverse = [bool]$tmp[0]
            $i = $tmp[1]
        } else {
            $i = Skip-Field $msg $i $wire
        }
    }
    return [pscustomobject]@{ Code = $code; Cidrs = $cidrs; Inverse = $inverse }
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
    $dType = 0
    $value = $null
    while ($i -lt $msg.Length) {
        $tmp = Read-Varint $msg $i
        $tag = $tmp[0]
        $i = $tmp[1]
        $field = [int]($tag -shr 3)
        $wire = [int]($tag -band 7)
        if ($field -eq 1 -and $wire -eq 0) {
            $tmp = Read-Varint $msg $i
            $dType = [int]$tmp[0]
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
    return [pscustomobject]@{ Type = $dType; Value = $value }
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
            $dmsg = $msg[$i..($i + $len - 1)]
            $i += $len
            $domains.Add((Parse-Domain $dmsg)) | Out-Null
        } else {
            $i = Skip-Field $msg $i $wire
        }
    }
    return [pscustomobject]@{ Code = $code; Domains = $domains }
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
        $b = [byte](($value -band 0x7F) -bor 0x80)
        $ms.WriteByte($b)
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
    if ($parts.Count -ne 2) { throw "Invalid CIDR: $cidr" }
    $ipStr = $parts[0].Trim()
    $prefix = [int]$parts[1].Trim()
    $ip = [System.Net.IPAddress]::Parse($ipStr)
    $ipBytes = $ip.GetAddressBytes()
    $ms = New-Object System.IO.MemoryStream
    Write-BytesField $ms 1 $ipBytes
    Write-UIntField $ms 2 ([UInt64]$prefix)
    return $ms.ToArray()
}

function Encode-GeoIP {
    param([string]$code, [System.Collections.Generic.List[string]]$cidrs, [bool]$inverse)
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
        $dmsg = Encode-Domain $domain.Type $domain.Value
        Write-BytesField $ms 2 $dmsg
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

function Export-GeoTxt {
    param([string]$geoipDat, [string]$geositeDat, [string]$geoipTxt, [string]$geositeTxt)
    $geoipData = [IO.File]::ReadAllBytes($geoipDat)
    $geositeData = [IO.File]::ReadAllBytes($geositeDat)

    $geoipEntries = Parse-GeoIPList $geoipData
    $geositeEntries = Parse-GeoSiteList $geositeData

    $geoipByCode = @{}
    $geoipOrder = New-Object 'System.Collections.Generic.List[string]'
    $geoipInverse = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($entry in $geoipEntries) {
        $code = $entry.Code
        if (-not $code) { $code = 'UNKNOWN' }
        if (-not $geoipByCode.ContainsKey($code)) {
            $geoipByCode[$code] = New-Object 'System.Collections.Generic.List[string]'
            $geoipOrder.Add($code) | Out-Null
        }
        if ($entry.Inverse) { $null = $geoipInverse.Add($code) }
        foreach ($cidr in $entry.Cidrs) { $geoipByCode[$code].Add($cidr) }
    }

    $sb = New-Object System.Text.StringBuilder
    foreach ($code in $geoipOrder) {
        $inv = if ($geoipInverse.Contains($code)) { ' (inverse)' } else { '' }
        $null = $sb.AppendLine("[$code]$inv")
        foreach ($cidr in $geoipByCode[$code]) { $null = $sb.AppendLine($cidr) }
        $null = $sb.AppendLine('')
    }
    [IO.File]::WriteAllText($geoipTxt, $sb.ToString(), [Text.Encoding]::UTF8)

    $typeMap = @{ 0 = 'plain'; 1 = 'regex'; 2 = 'domain'; 3 = 'full' }
    $geositeByCode = @{}
    $geositeOrder = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in $geositeEntries) {
        $code = $entry.Code
        if (-not $code) { $code = 'UNKNOWN' }
        if (-not $geositeByCode.ContainsKey($code)) {
            $geositeByCode[$code] = New-Object 'System.Collections.Generic.List[string]'
            $geositeOrder.Add($code) | Out-Null
        }
        foreach ($domain in $entry.Domains) {
            if (-not $domain.Value) { continue }
            $t = if ($typeMap.ContainsKey($domain.Type)) { $typeMap[$domain.Type] } else { [string]$domain.Type }
            $geositeByCode[$code].Add("${t}:$($domain.Value)")
        }
    }

    $sb2 = New-Object System.Text.StringBuilder
    foreach ($code in $geositeOrder) {
        $null = $sb2.AppendLine("[$code]")
        foreach ($item in $geositeByCode[$code]) { $null = $sb2.AppendLine($item) }
        $null = $sb2.AppendLine('')
    }
    [IO.File]::WriteAllText($geositeTxt, $sb2.ToString(), [Text.Encoding]::UTF8)
}

function Import-GeoTxt {
    param([string]$geoipTxt, [string]$geositeTxt, [string]$geoipDat, [string]$geositeDat)

    $geoipEntries = New-Object 'System.Collections.Generic.List[object]'
    $current = $null
    foreach ($raw in [IO.File]::ReadAllLines($geoipTxt)) {
        $line = $raw.Trim()
        if (-not $line) { continue }
        if ($line.StartsWith('#') -or $line.StartsWith('//')) { continue }
        if ($line -match '^\[(.+?)\]\s*(?:\((?i:inverse)\))?\s*$') {
            if ($current) { $geoipEntries.Add($current) | Out-Null }
            $code = $Matches[1]
            $inverse = ($line -match '(?i:inverse)')
            $current = [pscustomobject]@{
                Code = $code
                Cidrs = New-Object 'System.Collections.Generic.List[string]'
                Inverse = $inverse
            }
            continue
        }
        if (-not $current) { throw "CIDR without group header: $line" }
        $current.Cidrs.Add($line) | Out-Null
    }
    if ($current) { $geoipEntries.Add($current) | Out-Null }

    $typeToInt = @{ plain = 0; regex = 1; domain = 2; full = 3 }
    $geositeEntries = New-Object 'System.Collections.Generic.List[object]'
    $current = $null
    foreach ($raw in [IO.File]::ReadAllLines($geositeTxt)) {
        $line = $raw.Trim()
        if (-not $line) { continue }
        if ($line.StartsWith('#') -or $line.StartsWith('//')) { continue }
        if ($line -match '^\[(.+?)\]\s*$') {
            if ($current) { $geositeEntries.Add($current) | Out-Null }
            $code = $Matches[1]
            $current = [pscustomobject]@{
                Code = $code
                Domains = New-Object 'System.Collections.Generic.List[object]'
            }
            continue
        }
        if (-not $current) { throw "Domain without group header: $line" }
        $idx = $line.IndexOf(':')
        if ($idx -lt 0) { throw "Invalid domain line (expected type:value): $line" }
        $typeStr = $line.Substring(0, $idx).Trim()
        $value = $line.Substring($idx + 1).Trim()
        if (-not $value) { continue }
        if ($typeToInt.ContainsKey($typeStr)) {
            $typeInt = $typeToInt[$typeStr]
        } elseif ($typeStr -match '^\d+$') {
            $typeInt = [int]$typeStr
        } else {
            throw "Unknown domain type: $typeStr"
        }
        $current.Domains.Add([pscustomobject]@{ Type = $typeInt; Value = $value }) | Out-Null
    }
    if ($current) { $geositeEntries.Add($current) | Out-Null }

    $geoipBytes = Encode-GeoIPList $geoipEntries
    $geositeBytes = Encode-GeoSiteList $geositeEntries

    $tmpGeoip = "$geoipDat.tmp"
    $tmpGeosite = "$geositeDat.tmp"
    [IO.File]::WriteAllBytes($tmpGeoip, $geoipBytes)
    [IO.File]::WriteAllBytes($tmpGeosite, $geositeBytes)
    Move-Item -Force $tmpGeoip $geoipDat
    Move-Item -Force $tmpGeosite $geositeDat
}

if ($Mode -eq 'help') {
    Write-Output 'Usage:'
    Write-Output '  .\geo_tool.ps1 export   # dat -> txt'
    Write-Output '  .\geo_tool.ps1 import   # txt -> dat'
    Write-Output ''
    Write-Output 'Files:'
    Write-Output "  geoip.dat     <-> $GeoIpTxt"
    Write-Output "  geosite.dat   <-> $GeoSiteTxt"
    exit 0
}

if ($Mode -eq 'export') {
    Export-GeoTxt $GeoIpDat $GeoSiteDat $GeoIpTxt $GeoSiteTxt
    Write-Output "Exported to $GeoIpTxt and $GeoSiteTxt"
    exit 0
}

if ($Mode -eq 'import') {
    Import-GeoTxt $GeoIpTxt $GeoSiteTxt $GeoIpDat $GeoSiteDat
    Write-Output "Imported and rewrote $GeoIpDat and $GeoSiteDat"
    exit 0
}
