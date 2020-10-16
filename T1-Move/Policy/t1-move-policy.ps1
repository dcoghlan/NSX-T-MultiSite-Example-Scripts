# NSX-T - Basic DR for logical routing script (Policy).
# Author: Dale Coghlan
# Email: dcoghlan@vmware.com
# Date: 12th Mar 2019

# Version 0.1

# This script is intended to be used in a DR scenario to move T1 gateways to a
# pre-created standby T0 gateway on an existing edge cluster in the DR site.
# As this script interacts with the NSX-T API, and the NSX-T Managers would
# likely reside in the main site (which would become unavailable in a DR,
# scenario), it is intended to be run against a MP/CCP Cluster in the DR site 
# that has been restored from a backup of the primary sites MP/CCP Cluster.

# There are 2 main "modes" to run the sciprt in:
# - T0 mode
# - Cluster mode

# Both modes will require the user to enter the NSX Manager IP or FQDN,
# Username and Password, along with a Tag and Scope that will identify
# the T1 gateways that are required to be reallocated.

# In scenarios where the source edge cluster where the T1 is coming from, has
# more edge node members than the destination edge cluster, this will be flagged
# as a warning and the script won't pass the pre-check stage. This will give the
# user the opportunity to either add more nodes to the destination cluster, or
# if they understand the risk, they can supply the -IgnoreClusterSizeMisMatch
# parameter to ignore those specific tests.

# T0 Mode

# When run in this mode, the user will also specify the following:

# -SrcTier0 - The name of the source Tier 0 gateway. All connected T1 
#  gateways that are tagged for DR will be reallocated.

# -DstTier0 - The name of the destination Tier 0 gateway. All the Tier 1
#  gateways that are being reallocated will be connected to the destination 
#  Tier 0 gateway specified.

# -DstEdgeCluster - The ID or name of the destination edge cluster. If a T1 
#  gateway that has been tagged for reallocation is currently allocated to ANY
#  edge cluster, it will be reallocated to the destination edge cluster
#  specified. If you have T1 gateways spread across multiple edge clusters,
#  consider tagging them based on cluster, and running the script multiple
#  times with the appropriate tags to target different destination edge clusters.

# Cluster Mode

# When run in cluster mode, the script will look for all appropriatley tagged T1
# gateways with no T0 gateways connected, on the source cluster specified, and
# reallocate them to the destination cluster specified. The user must specify
# the following:

# -SrcEdgeCluster - The ID or name of the source edge cluster. If a T1 gateway
#  that has been tagged for reallocation is currently allocated to this cluster,
#  it will be reallocated to the destination edge cluster specified.

# -DstEdgeCluster - The ID or name of the destination edge cluster. If a T1
#  gateway that has been tagged for reallocation is currently allocated to an
#  edge cluster, it will be reallocated to the destination edge cluster
#  specified.

################################################################################
# ChangeLog
#
# v0.1 (Initial)


[CmdLetBinding(DefaultParameterSetName = "ClusterAndTier0SrcByName_DstByName")]

param (
    [parameter(Mandatory = $True)]
    # NSX Manager IP or FQDN.
    [ValidateNotNullOrEmpty()]
    [string] $NsxManager,
    [parameter(Mandatory = $True)]
    # Username used to authenticate to NSX API
    [ValidateNotNullOrEmpty()]
    [string] $Username,
    [parameter(Mandatory = $True)]
    # Password used to authenticate to NSX API
    [ValidateNotNullOrEmpty()]
    [string] $Password,
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0SrcByName_DstByName", HelpMessage = "Please enter name of the source Tier0 Gateway.")]
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0SrcByName_DstById")]
    [ValidateNotNullOrEmpty()]
    [string] $SrcTier0,
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0SrcById_DstByName")]
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0SrcById_DstById")]
    [ValidateNotNullOrEmpty()]
    [string] $SrcTier0Id,
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0SrcByName_DstByName", HelpMessage = "Please enter name of the destination Tier0 Gateway.")]
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0SrcById_DstByName")]
    [ValidateNotNullOrEmpty()]
    [string] $DstTier0,
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0SrcByName_DstById")]
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0SrcById_DstById")]
    [ValidateNotNullOrEmpty()]
    [string] $DstTier0Id,
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $SrcEdgeCluster,
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $DstEdgeCluster,
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $Tag,
    [parameter(Mandatory = $True)]
    [ValidateNotNullOrEmpty()]
    [string] $Scope,
    [parameter(Mandatory = $False)]
    [switch] $IgnoreClusterSizeMisMatch = $False
)

$StatusText1 = "PASS"
$StatusText2 = "FAIL"
$StatusText3 = "SKIPPED"

# ------------------------------------------------------------------------------
# No need to modify anything below this line.
# ------------------------------------------------------------------------------
#Requires -Version 5.1

# Record the script actual start time.
$start = Get-Date

$Errors = New-Object System.Collections.Arraylist
$Warnings = New-Object System.Collections.Arraylist
$Proceed = $True

$TagDisplayText = "Tag ($Tag)"
$ScopeDisplayText = "; Scope ($Scope)"

# Create the custom header for authentication
$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $Username, $Password)))
$headers = @{
    "Authorization" = ("Basic {0}" -f $base64AuthInfo);
    "Content-Type"  = "application/json"
}

function _init {

    if ( $psversiontable.psedition -eq "Desktop" ) {
        # Add TLS1.2 support
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Ssl3

        ## Define class required for certificate validation override.  Version dependant.
        ## For whatever reason, this does not work when contained within a function?
        $TrustAllCertsPolicy = @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
            }
        }
"@
    
        if ( -not ("TrustAllCertsPolicy" -as [type])) {
            Add-Type $TrustAllCertsPolicy
        }
    
        $script:originalCertPolicy = [System.Net.ServicePointManager]::CertificatePolicy
    }
}

function Invoke-NsxtRestMethod {

    param (
        [parameter(Mandatory = $True)]
        [ValidateSet("get", "put", "post", "delete", "patch")]
        [string]$method,
        [parameter(Mandatory = $True)]
        [string]$uri,
        [parameter(Mandatory = $True)]
        [hashtable]$headers = @{ },
        [parameter(Mandatory = $False)]
        [switch]$SkipCertificateCheck = $True,
        [parameter(Mandatory = $false)]
        [string]$body
    )
    if ($psversiontable.psedition -eq "Desktop") {
        #Use splatting to build up the IWR params
        $irmSplat = @{
            "method"  = $method;
            "headers" = $headers;
            "uri"     = $Uri;
        }

        if ( $PsBoundParameters.ContainsKey('Body')) {
            $irmSplat.Add("body", $body)
        }

        if (( -not $ValidateCertificate) -and ([System.Net.ServicePointManager]::CertificatePolicy.tostring() -ne 'TrustAllCertsPolicy')) {
            #allow untrusted certificate presented by the remote system to be accepted
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
        }
        Write-Debug $uri
        Invoke-RestMethod @irmSplat
    }
    else {
        #Use splatting to build up the IWR params
        $irmSplat = @{
            "method"  = $method;
            "headers" = $headers;
            "uri"     = $Uri;
        }

        if ( $PsBoundParameters.ContainsKey('Body')) {
            $irmSplat.Add("body", $body)
        }
        
        if ($PSBoundParameters.ContainsKey('SkipCertificateCheck')) {
            $irmSplat.Add("SkipCertificateCheck", $SkipCertificateCheck)
        }
        Write-Debug $uri
        Invoke-RestMethod @irmSplat
    }
}

function Invoke-DisplayTitle {
    Write-Host @"

    ___ _ ____ ____    ____ _  _ ____ 
     |  | |___ |__/    |  | |\ | |___ 
     |  | |___ |  \    |__| | \| |___ 
                                     
   ____ ____ ___ ____ _ _ _ ____ _   _    _  _ ____ _  _ ____ 
   | __ |__|  |  |___ | | | |__|  \_/     |\/| |  | |  | |___ 
   |__] |  |  |  |___ |_|_| |  |   |      |  | |__|  \/  |___ 
"@

}

function New-DisplayHeading {

    param (
        [string]$text
    )

    Write-Host "`n"
    Write-Host -ForegroundColor green ("-" * 80)
    Write-Host -ForegroundColor green "`n $text `n"
    Write-Host -ForegroundColor green ("-" * 80)

}

Function ValidateNsxtId {

    Param (
        [Parameter (Mandatory = $true)]
        [string]$argument
    )

    #check if we are valid NSX-T ID or name as a string
    if ( ($argument -is [string]) -and ($argument -match "^[0-9,a-f]{8}-[0-9,a-f]{4}-[0-9,a-f]{4}-[0-9,a-f]{4}-[0-9,a-f]{12}$" )) {
        $true
    }
    elseif ( ($argument -is [string]) ) {
        $false
    }
    else {
        throw "Argument supplied is not a string."
    }
}

function Get-PolicyTier1s {
    [CmdletBinding(DefaultParameterSetName = "Default")]

    param (
        [Parameter(Mandatory = $True, ParameterSetName = "ID")]
        [string] $Id
    )
    $uri = New-Object System.UriBuilder("https://$nsxManager")

    $uri.path = "/policy/api/v1/infra/tier-1s"

    if ($PSBoundParameters.ContainsKey('Id') ) {
        $uri.path = Join-Path $uri.path $Id
    }

    try {
        $response = Invoke-NsxtRestMethod -Method GET -URI $uri.uri -Headers $headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }

    if ($response.results) {
        $response.results | ForEach-Object { $results += @($_) }
        if ($response.cursor) {
            while ($response.cursor) {
                $uri.query = "cursor=" + $response.cursor
                try {
                    $response = Invoke-NsxtRestMethod -Method GET -URI $uri.uri -Headers $headers -SkipCertificateCheck
                }
                catch {
                    throw ($_)
                }
                $response.results | ForEach-Object { $results += @($_) }
            }
        }
        $results
    }
    else {
        $response
    }
}

function Get-PolicyTier1sLocaleServices {
    param (
        [Parameter(Mandatory = $True)]
        [string] $id
    )
    $uri = New-Object System.UriBuilder("https://$nsxManager")

    $uri.path = "/policy/api/v1/infra/tier-1s/$($id)/locale-services"
    try {
        $response = Invoke-NsxtRestMethod -Method GET -URI $uri -Headers $headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }
    $response.results
}

function Get-PolicyTier0s {
    [CmdletBinding(DefaultParameterSetName = "Default")]

    param (
        [Parameter(Mandatory = $True, ParameterSetName = "ID")]
        [string] $Id
    )
    $uri = New-Object System.UriBuilder("https://$nsxManager")

    $uri.path = "/policy/api/v1/infra/tier-0s"


    if ($PSBoundParameters.ContainsKey('Id') ) {
        $uri.path = Join-Path $uri.path $Id
    }

    try {
        $response = Invoke-NsxtRestMethod -Method GET -URI $uri -Headers $headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }

    if ($response.results) {
        $response.results | ForEach-Object { $results += @($_) }
        if ($response.cursor) {
            while ($response.cursor) {
                $uri.query = "cursor=" + $response.cursor
                try {
                    $response = Invoke-NsxtRestMethod -Method GET -URI $uri -Headers $headers -SkipCertificateCheck
                }
                catch {
                    throw ($_)
                }
                $response.results | ForEach-Object { $results += @($_) }
            }
        }
        $results
    }
    else {
        $response
    }
}

function Get-EnforcementPoint {
    param (
        [Parameter(Mandatory = $False)]
        [String] $SiteId = "default"
    )

    $uri = New-Object System.UriBuilder("https://$nsxManager")

    $uri.path = "/policy/api/v1/infra/sites/$SiteId/enforcement-points"

    try {
        $response = Invoke-NsxtRestMethod -Method GET -URI $uri -Headers $headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }
    $response.results

}

function Get-PolicyEdgeClusters {
    param (
        [Parameter(Mandatory = $True)]
        [String] $SiteId = "default",
        [Parameter(Mandatory = $True)]
        [String] $EnforcementPointId = "default"
    )
    $uri = New-Object System.UriBuilder("https://$nsxManager")

    $uri.path = "/policy/api/v1/infra/sites/$SiteId/enforcement-points/$EnforcementPointId/edge-clusters"

    try {
        $response = Invoke-NsxtRestMethod -Method GET -URI $uri -Headers $headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }
    $response.results

}

function Get-MpEdgeClusters {

    [CmdletBinding(DefaultParameterSetName = "Default")]

    param (
        [Parameter(Mandatory = $False, ParameterSetName = "ID")]
        [string] $EdgeClusterId
    )
    $results = @()
    $uri = New-Object System.UriBuilder("https://$nsxManager")
    $uri.path = "/api/v1/edge-clusters"

    if ($PSBoundParameters.ContainsKey('EdgeClusterId') ) {
        $uri.path = Join-Path $uri.path $EdgeClusterId

    } 

    try {
        $response = Invoke-NsxtRestMethod -Method GET -URI $uri.Uri -Headers $headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }

    if ($response.results) {
        $response.results | ForEach-Object { $results += @($_) }
        if ($response.cursor) {
            while ($response.cursor) {
                $uri.query = "cursor=" + $response.cursor
                try {
                    $response = Invoke-NsxtRestMethod -Method GET -URI $uri.Uri -Headers $headers -SkipCertificateCheck
                }
                catch {
                    throw ($_)
                }
                $response.results | ForEach-Object { $results += @($_) }
            }
        }
        $results
    } 
    else {
        $response
    }
}

function Invoke-CheckLogicalRouter {

    param (
        [parameter(Mandatory = $True)]
        [AllowNull()]
        [object[]] $Collection,
        [Parameter(Mandatory = $True)]
        [string] $Field,
        [Parameter(Mandatory = $True)]
        [string] $StringMatch
        
    )

    $object = $collection | Where-Object { $_.$($field) -eq $StringMatch }
    if (! ($object)) {
        Write-Host -ForegroundColor red $StatusText2
        $script:Errors.Add("Logical Gateway supplied ($($StringMatch)) does not exist.") | Out-Null
        $script:Proceed = $False
    }
    elseif ($object.count -ge 2) {
        Write-Host -ForegroundColor red $StatusText2
        $script:Errors.Add("Multiple logical gateways ($($object.count)) found matching name ($($StringMatch)). Specify ID instead.") | Out-Null
        $script:Proceed = $False
    }
    else {
        Write-Host -ForegroundColor Green "$StatusText1 `n   |--> (Name=$($object.display_name); ID=$($object.id))" 
    }

    $object
}

function Invoke-DisplayMessages {
    if ( ($Warnings) -OR ($Errors) ) {
        Write-Host "`n"
        Write-Host -ForegroundColor Yellow ("-" * 80)
        if ($Errors) {
            $Errors | ForEach-Object { Write-Host -ForegroundColor magenta "ERROR:"$_ }
        }
        if ($Warnings) {
            $Warnings | ForEach-Object { Write-Warning $_ }
        }
        Write-Host -ForegroundColor Yellow ("-" * 80)
        Write-Host "`n"
    }
}

function Invoke-ProceedCheck {
    if (!($proceed)) {
        Invoke-DisplayMessages
        exit
    } 
}

function Invoke-CheckEdgeClusterExists {

    param (
        [parameter(Mandatory = $True)]
        [object[]] $Collection,
        [Parameter(Mandatory = $True)]
        [string] $id
    )

    if (ValidateNsxtId $id) {
        $EdgeCluster = $Collection | Where-Object { $_.id -eq $id }
    }
    else {
        $EdgeCluster = $Collection | Where-Object { $_.display_name -eq $id }
    }

    if (! ($EdgeCluster)) {
        Write-Host -ForegroundColor red $StatusText2
        $script:Errors.Add("Edge cluster supplied ($($id)) does not exist.") | Out-Null
        $script:Proceed = $False
    }
    elseif ( $EdgeCluster.count -ge 2) {
        Write-Host -ForegroundColor red $StatusText2
        $script:Errors.Add("Multiple Edge clusters ($($EdgeCluster.count)) found matching name ($($id)). Specify ID instead.") | Out-Null
        $script:Proceed = $False
    }
    else {
        Write-Host -ForegroundColor Green "$StatusText1 `n   |--> (Name=$($EdgeCluster.display_name); ID=$($EdgeCluster.id))"
        $EdgeCluster 
    }
}

function Invoke-CheckEdgeClusterMembersExist {

    param (
        [parameter(Mandatory = $True)]
        [object[]] $EdgeCluster
    )

    if (($EdgeCluster.members | Measure-Object).count -eq 0) {
        Write-Host -ForegroundColor red "$StatusText2 `n   |--> (Count=$(($EdgeCluster.members | Measure-Object).count))"
        $Errors.Add("Destination edge cluster supplied does not have any members.") | Out-Null
        $script:Proceed = $False
        $False
    }
    else {
        Write-Host -ForegroundColor Green "$StatusText1 `n   |--> (Count=$(($EdgeCluster.members | Measure-Object).count))" 
        $True
    }

}

function Invoke-CheckSameNsxtObject {

    param (
        [parameter(Mandatory = $True)]
        [object] $object1,
        [parameter(Mandatory = $True)]
        [object] $object2
    )
    if ($object1.id -eq $object2.id) {
        # Objects are the same NSX-T object
        $Errors.Add("Identical objects specified. Name=$($object1.display_name); ID=$($object1.id)") | Out-Null
        $script:Proceed = $False
        $True
    }
    else {
        $False
    }

}

function Invoke-PatchPolicyObject {
    param (
        [parameter(Mandatory = $True)]
        [object] $path,
        [parameter(Mandatory = $True)]
        [string] $body
    )

    $uri = New-Object System.UriBuilder("https://$nsxManager/policy/api/v1")
    $uri.path += $path

    Write-Debug $path
    Write-Debug $body
    Invoke-NsxtRestMethod -method PATCH -body $body -uri $uri -SkipCertificateCheck -Headers $headers

}

# ------------------------------------------------------------------------------
# Pre-Checks
# ------------------------------------------------------------------------------
_init
Invoke-DisplayTitle
New-DisplayHeading "Gathering details"

Write-Host "  --> Retriving enforcement points... "
$enforcementPoint = Get-EnforcementPoint
if ($enforcementPoint) { Write-Debug $($enforcementPoint | ConvertTo-Json -Depth 100) }

Write-Host "  --> Retriving policy edge clusters... "
$PolicyEdgeClusters = Get-PolicyEdgeClusters -SiteId "default" -EnforcementPointId "default"
if ($PolicyEdgeClusters) { Write-Debug $($PolicyEdgeClusters | ConvertTo-Json -Depth 100) }

Write-Host "  --> Retriving manager edge clusters... "
$MpEdgeClusters = Get-MpEdgeClusters
if ($MpEdgeClusters) { Write-Debug $($MpEdgeClusters | ConvertTo-Json -Depth 100) }

Write-Host "  --> Retriving T0 Gateways... "
$policyTier0Routers = Get-PolicyTier0s
if ($policyTier0Routers) { Write-Debug $($policyTier0Routers | ConvertTo-Json -Depth 100) }

Write-Host "  --> Retriving T1 Gateways... "
$policyTier1Routers = Get-PolicyTier1s
if ($policyTier1Routers) { Write-Debug $($policyTier1Routers | ConvertTo-Json -Depth 100) }

New-DisplayHeading "Performing Pre-Checks"

if (! ($policyTier0Routers) ) {
    $script:Errors.Add("No Tier0 Gateways configured.") | Out-Null
    $script:Proceed = $False
}

if (! ($policyTier1Routers) ) {
    $script:Errors.Add("No Tier1 Gateways configured.") | Out-Null
    $script:Proceed = $False
}

Invoke-ProceedCheck

$lookupFieldDisplayName = "display_name"
$lookupFieldId = "id"

switch ($PSCmdlet.ParameterSetName) {
    "ClusterAndTier0SrcByName_DstByName" {
        $SrcTier0Supplied = $SrcTier0
        $SrcTier0LookupField = $lookupFieldDisplayName
        $DstTier0Supplied = $DstTier0
        $DstTier0LookupField = $lookupFieldDisplayName
        Break
    }
    "ClusterAndTier0SrcByName_DstById" {
        $SrcTier0Supplied = $SrcTier0
        $SrcTier0LookupField = $lookupFieldDisplayName
        $DstTier0Supplied = $DstTier0Id
        $DstTier0LookupField = $lookupFieldId
        Break
    }
    "ClusterAndTier0SrcById_DstByName" {
        $SrcTier0Supplied = $SrcTier0Id
        $SrcTier0LookupField = $lookupFieldId
        $DstTier0Supplied = $DstTier0
        $DstTier0LookupField = $lookupFieldDisplayName
        Break
    }
    "ClusterAndTier0SrcById_DstById" {
        $SrcTier0Supplied = $SrcTier0Id
        $SrcTier0LookupField = $lookupFieldId
        $DstTier0Supplied = $DstTier0Id
        $DstTier0LookupField = $lookupFieldId
        Break
    }

}

if ($PSCmdlet.ParameterSetName -match "^ClusterAndTier0") {
    # Run verification tasks for gateways 
    Write-Host -NoNewline "`n  --> Verifying source Tier 0 Gateway by $($SrcTier0LookupField) ($SrcTier0Supplied)... "
    $policySrcTier0Router = Invoke-CheckLogicalRouter -Collection $policyTier0Routers -Field $SrcTier0LookupField -StringMatch $SrcTier0Supplied
    if ($policySrcTier0Router) { Write-Debug $($policySrcTier0Router | ConvertTo-Json -Depth 100) }

    Write-Host -NoNewline "`n  --> Verifying destination Tier 0 Gateway by $($DstTier0LookupField) ($DstTier0Supplied)... "
    $policyDstTier0Router = Invoke-CheckLogicalRouter -Collection $policyTier0Routers -Field $DstTier0LookupField -StringMatch $DstTier0Supplied
    if ($policyDstTier0Router) { Write-Debug $($policyDstTier0Router | ConvertTo-Json -Depth 100) }

    Write-Host -NoNewline "`n  --> Verifying destination edge cluster ($DstEdgeCluster)... "
    $dstEdgeClusterPolicyObject = Invoke-CheckEdgeClusterExists -Collection $PolicyEdgeClusters -id $DstEdgeCluster
    if ($dstEdgeClusterPolicyObject) { Write-Debug $($dstEdgeClusterPolicyObject | ConvertTo-Json -Depth 100) }

    Invoke-ProceedCheck

    Write-Host -NoNewline "`n  --> Verifying member count of destination edge cluster ($DstEdgeCluster)... "
    $dstEdgeClusterMpObject = $MpEdgeClusters | Where-Object { $_.id -eq $dstEdgeClusterPolicyObject.nsx_id }
    if ($dstEdgeClusterMpObject) { Write-Debug $($dstEdgeClusterMpObject | ConvertTo-Json -Depth 100) }
    Invoke-CheckEdgeClusterMembersExist -EdgeCluster $dstEdgeClusterMpObject | Out-Null

    Invoke-ProceedCheck

    Invoke-CheckSameNsxtObject -object1 $policySrcTier0Router -object2 $policyDstTier0Router | Out-Null

    Invoke-ProceedCheck

    Write-Host -NoNewline "`n  --> Finding all Tier1 gateways tagged with: $TagDisplayText$ScopeDisplayText... "

    $Tier1LinkedRouters = $policyTier1Routers | Where-Object { $_.tier0_path -eq $policySrcTier0Router.path }
    if ($Tier1LinkedRouters) { Write-Debug $($Tier1LinkedRouters | ConvertTo-Json -Depth 100) }

    $LogicalTier1RouterToDr = $Tier1LinkedRouters | Where-Object { if ($_.tags) { ($_.tags.GetEnumerator().tag -eq $tag) -AND ($_.tags.GetEnumerator().scope -eq "$scope") } }
    if ($LogicalTier1RouterToDr) { Write-Debug $($LogicalTier1RouterToDr | ConvertTo-Json -Depth 100) }

}
else {
    # Run verification tasks for gateways with no T0s connected
    Write-Host -NoNewline "`n  --> Verifying source edge cluster ($SrcEdgeCluster)... "
    $srcEdgeClusterPolicyObject = Invoke-CheckEdgeClusterExists -Collection $PolicyEdgeClusters -id $SrcEdgeCluster
    if ($srcEdgeClusterPolicyObject) { Write-Debug $($srcEdgeClusterPolicyObject | ConvertTo-Json -Depth 100) }

    Write-Host -NoNewline "`n  --> Verifying destination edge cluster ($DstEdgeCluster)... "
    $dstEdgeClusterPolicyObject = Invoke-CheckEdgeClusterExists -Collection $PolicyEdgeClusters -id $DstEdgeCluster
    if ($dstEdgeClusterPolicyObject) { Write-Debug $($dstEdgeClusterPolicyObject | ConvertTo-Json -Depth 100) }

    Invoke-ProceedCheck

    Invoke-CheckSameNsxtObject -object1 $srcEdgeClusterPolicyObject -object2 $dstEdgeClusterPolicyObject | Out-Null

    Invoke-ProceedCheck

    Write-Host -NoNewline "`n  --> Finding all Tier1 gateways tagged with: $TagDisplayText$ScopeDisplayText... "

    $Tier1TaggedGateways = $policyTier1Routers | Where-Object { if ($_.tags) { ($_.tags.GetEnumerator().tag -eq $tag) -AND ($_.tags.GetEnumerator().scope -eq "$scope") -AND (! ($_.tier0_path)) } }
    $LogicalTier1RouterToDr = New-Object System.Collections.ArrayList

    if ($Tier1TaggedGateways) {
        Write-Debug $($Tier1TaggedGateways | ConvertTo-Json -Depth 100)
        foreach ($T1TaggedGateway in $Tier1TaggedGateways) {
            $localeServices = Get-PolicyTier1sLocaleServices -id $T1TaggedGateway.id
            if ($localeServices.edge_cluster_path -eq $srcEdgeClusterPolicyObject.path) {
                $LogicalTier1RouterToDr.Add($T1TaggedGateway) | Out-Null
            }
        }
    }   
}

# From here on is executed by all choices.

if (! ($LogicalTier1RouterToDr) ) {
    Write-Host -ForegroundColor red "$StatusText2 `n   |--> (Count=$($LogicalTier1RouterToDr.count))"
    $Warnings.Add("No Tier1 Logical gateways found that are tagged with: $TagDisplayText$ScopeDisplayText.") | Out-Null
    $Proceed = $False
}
else {
    Write-Host -ForegroundColor Green "$StatusText1 `n   |--> (Count=$(($LogicalTier1RouterToDr | Measure-Object).count))"
}
Invoke-ProceedCheck

# Compare the edge cluster size of the source and destination clusters (if required).
ForEach ($SrcT1Router in $LogicalTier1RouterToDr) {
    Write-Host -NoNewline "`n    |--> Tier1 gateway: $($SrcT1Router.display_name)($($SrcT1Router.id))`n      |--> Matching edge cluster members check... "
    if ($IgnoreClusterSizeMisMatch) {
        Write-Host -ForegroundColor Yellow $StatusText3
    }
    else {
        $EdgeClusterSizeMismatch = $False
        $SrcT1LocaleServices = Get-PolicyTier1sLocaleServices -id $SrcT1Router.id

        if ($SrcT1LocaleServices.edge_cluster_path) {
            $SrcEdgeClusterPolicyObject = $PolicyEdgeClusters | Where-Object { $_.path -eq $SrcT1LocaleServices.edge_cluster_path }
            $SrcEdgeClusterMPObject = $MpEdgeClusters | Where-Object { $_.id -eq $SrcEdgeClusterPolicyObject.nsx_id }
            $DstEdgeClusterMPObject = $MpEdgeClusters | Where-Object { $_.id -eq $dstEdgeClusterPolicyObject.nsx_id }
            if ($DstEdgeClusterMPObject.members.count -lt $SrcEdgeClusterMPObject.members.count) {
                $EdgeClusterSizeMismatch = $True
                $Warnings.Add("Cluster member size mismatch.`
            Tier 1 Gateway: $($SrcT1Router.display_name)($($SrcT1Router.id)).`
            Source Edge Cluster: $($SrcEdgeClusterPolicyObject.display_name) ($($SrcEdgeClusterPolicyObject.id)); Edge node members: $($SrcEdgeClusterMPObject.members.count).`
            Destination Edge Cluster: $($dstEdgeClusterPolicyObject.display_name) ($($dstEdgeClusterPolicyObject.id)); Edge node members: $($DstEdgeClusterMPObject.members.count).`
            The destination edge cluster has less member nodes than the source edge cluster. Reallocating this T1 gateway could have an non-optimal affect on its performance.`
            To ignore this warning and skip this check, run the script again using the -IgnoreClusterSizeMisMatch parameter.") | Out-Null

            }
        }
        if ($EdgeClusterSizeMismatch -eq $True) {
            Write-Host -ForegroundColor Red "FAIL"
            $Proceed = $False
        }
        else {
            Write-Host -ForegroundColor Green $StatusText1
        }
    }
}
Invoke-ProceedCheck

# ------------------------------------------------------------------------------
# Time to move the T1 Gateways
# ------------------------------------------------------------------------------

New-DisplayHeading "Re-Allocating Tier 1 Gateways"

ForEach ($T1Gateway in $LogicalTier1RouterToDr) {
    Write-Host -ForegroundColor cyan "`n Processing Tier 1 Gateway: $($T1Gateway.display_name) ($($T1Gateway.id)) `n"

    # Re-Allocating T1 to new edge cluster (if currently assigned to an edge cluster)
    $T1LocaleServices = Get-PolicyTier1sLocaleServices -id $T1Gateway.id
    if ($T1LocaleServices) {
        Write-Debug $($T1LocaleServices | ConvertTo-Json -Depth 100)
        if ($T1LocaleServices.edge_cluster_path) {
            Write-Host "  --> Re-Allocating Tier1 gateway edge cluster: $($T1Gateway.display_name) ($($T1Gateway.id))`n   |--> Target Edge Cluster: $($dstEdgeClusterPolicyObject.display_name) ($($dstEdgeClusterPolicyObject.id))"
            $T1LocaleServices.edge_cluster_path = $dstEdgeClusterPolicyObject.path
            Invoke-PatchPolicyObject -path $($T1LocaleServices.path) -body ($T1LocaleServices | ConvertTo-Json) | Out-Null
        }
    }

    # Re-Connect T1 Gateway to destination T0 Gateway
    $T1Gateway = Get-PolicyTier1s -Id $T1Gateway.id
    if ($T1Gateway) {
        Write-Debug $($T1Gateway | ConvertTo-Json -Depth 100)
        if ($T1Gateway.tier0_path) {
            $T1Gateway.tier0_path = $policyDstTier0Router.path
            Write-Host "  --> Re-Connecting Tier1 gateway: $($T1Gateway.display_name) ($($T1Gateway.id))`n   |--> Target Tier0 gateway: $($policyDstTier0Router.display_name) ($($policyDstTier0Router.id))"
            Invoke-PatchPolicyObject -Path $T1Gateway.path -body ($T1Gateway | ConvertTo-Json) | Out-Null
        }
    }

}

$time = $((Get-Date) - $start)
New-DisplayHeading "Script runtime: $($time.Hours):$($time.Minutes):$($Time.Seconds)"
# ------------------------------------------------------------------------------
# Finish
# ------------------------------------------------------------------------------