# NSX-T - Basic DR for logical routing script.
# Author: Dale Coghlan
# Email: dcoghlan@vmware.com
# Date: 11th Jan 2019

# Version 0.2

# This script is intended to be used in a DR scenario to move T1 routers to a
# pre-created standby T0 router on an existing edge cluster in the DR site.
# As this script interacts with the NSX-T API, and the NSX-T Managers would
# likely reside in the main site (which would become unavailable in a DR,
# scenario), it is intended to be run against a MP/CCP Cluster in the DR site 
# that has been restored from a backup of the primary sites MP/CCP Cluster.

# There are 2 main "modes" to run the script in:
# - T0 mode
# - Cluster mode

# Both modes will require the user to enter the NSX Manager IP or FQDN,
# Username and Password, along with a Tag and Scope that will identify
# the T1 routers that are required to be reallocated.

# In scenarios where the source edge cluster where the T1 is coming from, has
# more edge node members than the destination edge cluster, this will be flagged
# as a warning and the script won't pass the pre-check stage. This will give the
# user the opportunity to either add more nodes to the destination cluster, or
# if they understand the risk, they can supply the -IgnoreClusterSizeMisMatch
# parameter to ignore those specific tests.

# T0 Mode

# When run in this mode, the user will also specify the following:

# -SrcTier0 - The ID or name of the source Tier 0 router. All connected T1 
#  routers that are tagged for DR will be reallocated.

# -DstTier0 - The ID or name of the destination Tier 0 router. All the Tier 1
#  routers that are being reallocated will be connected to the destination 
#  Tier 0 router specified.

# -DstEdgeCluster - The ID or name of the destination edge cluster. If a T1 
#  router that has been tagged for reallocation is currently allocated to ANY
#  edge cluster, it will be reallocated to the destination edge cluster
#  specified. If you have T1 routers spread across multiple edge clusters,
#  consider tagging them based on cluster, and running the script multiple
#  times with the appropriate tags to target different destination edge clusters.

# Cluster Mode

# When run in cluster mode, the script will look for all appropriatley tagged T1
# routers with no T0 routers connected, on the source cluster specified, and
# reallocate them to the destination cluster specified. The user will also
# specify the following:

# -SrcEdgeCluster - The ID or name of the source edge cluster. If a T1 router
#  that has been tagged for reallocation is currently allocated to this cluster,
#  it will be reallocated to the destination edge cluster specified.

# -DstEdgeCluster - The ID or name of the destination edge cluster. If a T1
#  router that has been tagged for reallocation is currently allocated to an
#  edge cluster, it will be reallocated to the destination edge cluster
#  specified.

################################################################################
# ChangeLog
#
# v0.2 (5th Feb 2019)
# - Updated help text
# - Enforce minimum version of Powershell 5.1
# - Renamed parameters to remove "Id" from parameter name
# - Implemented checks to determine if name or id has been specified for:
#   - SrcTier0
#   - DstTier0
#   - SrcEdgeCluster
#   - DstEdgeCluster
# - Implemented validation when specifying a source or destination object by
#   name, if multiple objects are found matching the name then an error is
#   displayed
# - Linked router ports that get deleted and re-created by the script will now
#   preserve any original tags configured on the ports
# - script will now perform validation on retrieved source and destination 
#   objects to verify that the objects are not the same
# - Support for both Powershell on Windows and Linux

[CmdLetBinding(DefaultParameterSetName = "ClusterAndTier0")]

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
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0")]
    [ValidateNotNullOrEmpty()]
    [string] $SrcTier0,
    [parameter(Mandatory = $True, ParameterSetName = "ClusterAndTier0")]
    [ValidateNotNullOrEmpty()]
    [string] $DstTier0,
    [parameter(Mandatory = $True, ParameterSetName = "ClusterOnlyNoTier0")]
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
        [hashtable]$headers = @{},
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
                                     
   ____ ____ _  _ ___ ____ ____    _  _ ____ _  _ ____ 
   |__/ |  | |  |  |  |___ |__/    |\/| |  | |  | |___ 
   |  \ |__| |__|  |  |___ |  \    |  | |__|  \/  |___ 
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
    Write-Host "`n"

}

Function ValidateNsxtId {

    Param (
        [Parameter (Mandatory = $true)]
        [string]$argument
    )

    #check if we are valid NSX-T ID or name as a string
    if ( ($argument -is [string]) -and ($argument -match "^[0-9,a-f]{8}-[0-9,a-f]{4}-[0-9,a-f]{4}-[0-9,a-f]{4}-[0-9,a-f]{12}$" )) {
        #argument is NSX-T ID string
        $true
    }
    elseif ( ($argument -is [string]) ) {
        #Argument is a name
        $false
    }
    else {
        throw "Argument supplied is not a string."
    }
}

function Get-LogicalRouter {

    [CmdletBinding(DefaultParameterSetName = "Default")]

    param (
        [parameter(Mandatory = $False, ParameterSetName = "Default")]
        [ValidateSet("TIER0", "TIER1", IgnoreCase = $false)]
        [string] $RouterType,
        [Parameter(Mandatory = $False, ParameterSetName = "ID")]
        [string] $LogicalRouterId
    )
    $results = @()
    $uri = "https://$nsxManager/api/v1/logical-routers"

    if ($PSBoundParameters.ContainsKey('RouterType') ) {
        $uri = $uri + "?router_type=" + $RouterType
    }

    if ($PSBoundParameters.ContainsKey('LogicalRouterId') ) {
        $uri = $uri + "/" + $LogicalRouterId
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
                $cursorUri = $uri + "&cursor=" + $response.cursor
                try {
                    $response = Invoke-NsxtRestMethod -Method GET -URI $cursorUri -Headers $headers -SkipCertificateCheck
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
        # The results set only contains a single item
        $response
    }
}

function Get-LogicalRouterPort {

    [CmdletBinding(DefaultParameterSetName = "Default")]

    param (
        [parameter(Mandatory = $False)]
        [ValidateSet("LogicalRouterUpLinkPort", "LogicalRouterDownLinkPort", "LogicalRouterLinkPortOnTIER0", "LogicalRouterLinkPortOnTIER1", "LogicalRouterLoopbackPort", "LogicalRouterIPTunnelPort", "LogicalRouterCentralizedServicePort", IgnoreCase = $false)]
        [string] $ResourceType,
        [Parameter(Mandatory = $False)]
        [string] $LogicalRouterId,
        [Parameter(Mandatory = $False, ParameterSetName = "PortId")]
        [string] $LogicalRouterPortId
    )

    $results = @()

    if ( $PSCmdlet.ParameterSetName -eq "PortId" ) {
        $uri = "https://$nsxManager/api/v1/logical-router-ports/$LogicalRouterPortId"
    } 
    else {
        $uri = "https://$nsxManager/api/v1/logical-router-ports?"

        if ($PSBoundParameters.ContainsKey('ResourceType') ) {
            $uri = $uri + "&resource_type=" + $ResourceType
        }
    
        if ($PSBoundParameters.ContainsKey('LogicalRouterId') ) {
            $uri = $uri + "&logical_router_id=" + $LogicalRouterId
        }
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
                $cursorUri = $uri + "&cursor=" + $response.cursor
                try {
                    $response = Invoke-NsxtRestMethod -Method GET -URI $cursorUri -Headers $headers -SkipCertificateCheck
                }
                catch {
                    throw ($_)
                }
                $response.results | ForEach-Object { $results += @($_) }
            }
        }
        $results
    } 
    elseif ( $PSCmdlet.ParameterSetName -eq "PortId" ) {
        $response
    }
    else {
        # The results set only contains a single item
        $response.results
    }
}

function Remove-LogicalRouterPort {

    param (
        [Parameter(Mandatory = $True)]
        [string[]] $id
    )

    ForEach ($portId in $id) {

        $uri = "https://$nsxManager/api/v1/logical-router-ports/$id"

        try {
            $response = Invoke-NsxtRestMethod -Method DELETE -URI $uri -Headers $headers -SkipCertificateCheck
        }
        catch {
            throw ($_)
        }
    }
}

function New-LogicalRouterLinkPort {
    param(
        [parameter(Mandatory = $True)]
        [ValidateSet("LogicalRouterLinkPortOnTIER0", "LogicalRouterLinkPortOnTIER1", IgnoreCase = $false)]
        [string] $ResourceType,
        [Parameter(Mandatory = $True)]
        [string] $LogicalRouterId,
        [Parameter(Mandatory = $False)]
        [string] $Description,
        [Parameter(Mandatory = $False)]
        [string] $DisplayName,
        [Parameter(Mandatory = $False)]
        [string] $LinkedLoficalRouterPortId,
        [Parameter(Mandatory = $False)]
        [object[]] $Tags
    )

    $uri = "https://$nsxManager/api/v1/logical-router-ports"

    $payload = @{
        "resource_type"     = $ResourceType;
        "logical_router_id" = $LogicalRouterId; 
    }
    if ($PSBoundParameters.ContainsKey("DisplayName")) {
        $payload.Add("display_name", $DisplayName)
    }
    if ($PSBoundParameters.ContainsKey("Description")) {
        $payload.Add("description", $Description)
    }
    if ($PSBoundParameters.ContainsKey("LinkedLoficalRouterPortId")) {
        $ResourceReference = @{
            "target_id" = $LinkedLoficalRouterPortId;
        }
        $payload.Add("linked_logical_router_port_id", $ResourceReference)
    }
    if ($PSBoundParameters.ContainsKey("Tags")) {
        $payload.Add("tags", @($tags))
    }
    
    $body = $payload | ConvertTo-Json

    try {
        $response = Invoke-NsxtRestMethod -Method POST -URI $uri -Headers $headers -body $body -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }

    $response
}

function Get-EdgeCluster {

    [CmdletBinding(DefaultParameterSetName = "Default")]

    param (
        [Parameter(Mandatory = $False, ParameterSetName = "ID")]
        [string] $EdgeClusterId,
        [Parameter(Mandatory = $False, ParameterSetName = "Default")]
        [ValidateRange(0, 1000)]
        [int] $page_size = 1000
    )
    $results = @()
    $uriBuilder = New-Object System.UriBuilder("https://$nsxManager")
    $uriBuilder.path = "/api/v1/edge-clusters"

    if ($PSBoundParameters.ContainsKey('EdgeClusterId') ) {
        $uriBuilder.path = "/api/v1/edge-clusters/$EdgeClusterId"
    } 
    if ($PSBoundParameters.ContainsKey('page_size') ) {
        $uriBuilder.query += "&page_size=$page_size"
    }

    $uriBuilder
    try {
        $response = Invoke-NsxtRestMethod -Method GET -URI $uriBuilder.Uri -Headers $headers -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }
    $response | ConvertTo-Json
    if ($response.results) {
        $response.results | ForEach-Object { $results += @($_) }
        if ($response.cursor) {
            while ($response.cursor) {
                $uriBuilder.query += "&cursor=$($response.cursor)"
                try {
                    $response = Invoke-NsxtRestMethod -Method GET -URI $uriBuilder.Uri -Headers $headers -SkipCertificateCheck
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
        # The results set only contains a single item
        $response
    }
}

function Invoke-ReAllocateT1Router {

    param (
        [parameter(Mandatory = $True)]
        [string] $EdgeClusterId,
        [Parameter(Mandatory = $True)]
        [string] $LogicalRouterId
    )

    $uri = "https://$nsxManager/api/v1/logical-routers/" + $LogicalRouterId + "?action=reallocate"

    $payload = @{
        edge_cluster_id = $EdgeClusterId;
    }
    $body = $payload | ConvertTo-Json

    try {
        $response = Invoke-NsxtRestMethod -Method POST -URI $uri -Headers $headers -body $body -SkipCertificateCheck
    }
    catch {
        throw ($_)
    }

    $response
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

function Invoke-CheckLogicalRouterExists {

    param (
        [parameter(Mandatory = $True)]
        [object[]] $Collection,
        [parameter(Mandatory = $True)]
        [ValidateSet("TIER0", "TIER1", IgnoreCase = $false)]
        [string] $Type,
        [Parameter(Mandatory = $True)]
        [string] $id
    )

    if (ValidateNsxtId $id) {
        $LogicalRouter = $Collection | Where-Object { ($_.id -eq $id) -AND ($_.router_type -eq $Type) }
    }
    else {
        $LogicalRouter = $Collection | Where-Object { ($_.display_name -eq $id) -AND ($_.router_type -eq $Type) }
    }
    if (! ($LogicalRouter)) {
        Write-Host -ForegroundColor red $StatusText2
        $script:Errors.Add("Logical router supplied ($($id)) does not exist.") | Out-Null
        $script:Proceed = $False
    }
    elseif ($LogicalRouter.count -ge 2) {
        Write-Host -ForegroundColor red $StatusText2
        $script:Errors.Add("Multiple logical routers ($($LogicalRouter.count)) found matching name ($($id)). Specify ID instead.") | Out-Null
        $script:Proceed = $False
    }
    else {
        Write-Host -ForegroundColor Green "$StatusText1 `n   |--> (Name=$($LogicalRouter.display_name); ID=$($LogicalRouter.id))" 
    }

    $LogicalRouter
}

function Invoke-CheckEdgeClusterExists {

    param (
        [parameter(Mandatory = $True)]
        [object[]] $Collection,
        [Parameter(Mandatory = $True)]
        [string] $id
    )

    if (ValidateNsxtId $id) {
        $EdgeCluster = $EdgeClusters | Where-Object { $_.id -eq $id }
    }
    else {
        $EdgeCluster = $EdgeClusters | Where-Object { $_.display_name -eq $id }
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
        Write-Host -ForegroundColor Green "$StatusText1 `n   |--> Count=$(($EdgeCluster.members | Measure-Object).count)" 
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

# ------------------------------------------------------------------------------
# Pre-Checks
# ------------------------------------------------------------------------------
_init
Invoke-DisplayTitle
New-DisplayHeading "Performing Pre-Checks"

$LogicalRouters = Get-LogicalRouter
$EdgeClusters = Get-EdgeCluster

if ( $PSCmdlet.ParameterSetName -eq "ClusterAndTier0" ) {
    # Check the source T0 router exists
    Write-Host -NoNewline "`n  --> Verifying source Tier 0 Router ($SrcTier0)... "
    $SrcTier0LogicalRouter = Invoke-CheckLogicalRouterExists -Collection $LogicalRouters -Type TIER0 -id $SrcTier0

    # Check the destination T0 router exists
    Write-Host -NoNewline "`n  --> Verifying destination Tier 0 Router ($DstTier0)... "
    $DstTier0LogicalRouter = Invoke-CheckLogicalRouterExists -Collection $LogicalRouters -Type TIER0 -id $DstTier0

    # Check the destination edge cluster exists
    Write-Host -NoNewline "`n  --> Verifying destination edge cluster ($DstEdgeCluster)... "
    $dstEdgeClusterObject = Invoke-CheckEdgeClusterExists -Collection $EdgeClusters -id $DstEdgeCluster

    Invoke-ProceedCheck

    Write-Host -NoNewline "`n  --> Verifying member count of destination edge cluster ($DstEdgeCluster)... "
    Invoke-CheckEdgeClusterMembersExist -EdgeCluster $dstEdgeClusterObject | Out-Null

    Invoke-ProceedCheck

    Invoke-CheckSameNsxtObject -object1 $SrcTier0LogicalRouter -object2 $DstTier0LogicalRouter | Out-Null

    Invoke-ProceedCheck

    # Given the source T0 router, find all T1 routers that are connected to the source Tier0 router
    Write-Host -NoNewline "`n  --> Finding all Tier1 routers tagged with: $TagDisplayText$ScopeDisplayText... "
    $SrcTier0LinkedPorts = Get-LogicalRouterPort -ResourceType LogicalRouterLinkPortOnTIER0 -LogicalRouterId $SrcTier0LogicalRouter.id
    $Tier1LinkedPorts = Get-LogicalRouterPort -ResourceType LogicalRouterLinkPortOnTIER1 | Where-Object { if ($_.linked_logical_router_port_id) { $SrcTier0LinkedPorts.id -contains $_.linked_logical_router_port_id.target_id } }
    $Tier1LinkedRouters = $LogicalRouters | Where-Object { ($_.router_type -eq "TIER1") -AND ($Tier1LinkedPorts.logical_router_id -contains $_.id) } 

    # Figure out which of the connected T1 routers are to be DR'd based on scope/tag
    $LogicalTier1RouterToDr = $Tier1LinkedRouters | Where-Object { if ($_.tags) { ($_.tags.GetEnumerator().tag -eq $tag) -AND ($_.tags.GetEnumerator().scope -eq "$scope") } }

}

if ( $PSCmdlet.ParameterSetName -eq "ClusterOnlyNoTier0" ) {
    # Check the destination edge cluster exists
    Write-Host -NoNewline "  --> Verifying source edge cluster ($SrcEdgeCluster)... "
    $srcEdgeClusterObject = Invoke-CheckEdgeClusterExists -Collection $EdgeClusters -id $SrcEdgeCluster

    # Check the destination edge cluster exists
    Write-Host -NoNewline "  --> Verifying destination edge cluster ($DstEdgeCluster)... "
    $dstEdgeClusterObject = Invoke-CheckEdgeClusterExists -Collection $EdgeClusters -id $DstEdgeCluster

    Invoke-ProceedCheck

    Write-Host -NoNewline "  --> Verifying member count of destination edge cluster ($DstEdgeCluster)... "
    Invoke-CheckEdgeClusterMembersExist -EdgeCluster $dstEdgeClusterObject | Out-Null

    Invoke-ProceedCheck

    Invoke-CheckSameNsxtObject -object1 $srcEdgeClusterObject -object2 $dstEdgeClusterObject | Out-Null

    Invoke-ProceedCheck

    Write-Host -NoNewline "  --> Finding all Tier1 routers tagged with: $TagDisplayText$ScopeDisplayText... "
    $T1RoutersOnCluster = $LogicalRouters | Where-Object { ($_.edge_cluster_id -eq $srcEdgeClusterObject.id) -AND ($_.router_type -eq "TIER1") }
    $TaggedT1RoutersOnCluster = $T1RoutersOnCluster | Where-Object { if ($_.tags) { ($_.tags.GetEnumerator().tag -eq $Tag) -AND ($_.tags.GetEnumerator().scope -eq $Scope) } }
    $Tier1LinkedPorts = Get-LogicalRouterPort -ResourceType LogicalRouterLinkPortOnTIER1

    $LogicalTier1RouterToDr = New-Object System.Collections.Arraylist
    ForEach ($TaggedT1Router in $TaggedT1RoutersOnCluster) { if (! ($Tier1LinkedPorts | Where-Object { $_.logical_router_id -eq $TaggedT1Router.id })) { $LogicalTier1RouterToDr.Add($TaggedT1Router) | Out-Null } }

}

if (! ($LogicalTier1RouterToDr) ) {
    Write-Host -ForegroundColor red "$StatusText2 `n   |--> (Count=$($LogicalTier1RouterToDr.count))"
    $Warnings.Add("No Tier1 Logical routers found that are tagged with: $TagDisplayText$ScopeDisplayText.") | Out-Null
    $Proceed = $False
}
else {
    Write-Host -ForegroundColor Green "$($LogicalTier1RouterToDr.count) found."
}

# Compare the edge cluster size of the source and destination clusters (if required).
ForEach ($SrcT1Router in $LogicalTier1RouterToDr) {
    Write-Host -NoNewline "`n    |--> Tier1 router: $($SrcT1Router.display_name)($($SrcT1Router.id))`n      |--> Matching edge cluster members check... "
    if ($IgnoreClusterSizeMisMatch) {
        Write-Host -ForegroundColor Yellow $StatusText3
    }
    else {
        $EdgeClusterSizeMismatch = $False

        if ($SrcT1Router.edge_cluster_id) {
            $srcEdgeClusterMemberCompareObject = $EdgeClusters | Where-Object { $_.id -eq $SrcT1Router.edge_cluster_id }
            if ($dstEdgeClusterObject.members.count -lt $srcEdgeClusterMemberCompareObject.members.count) {
                $EdgeClusterSizeMismatch = $True
                $Warnings.Add("Cluster member size mismatch.`
            Tier 1 router: $($SrcT1Router.display_name)($($SrcT1Router.id)).`
            Source Edge Cluster: $($srcEdgeClusterMemberCompareObject.display_name) ($($srcEdgeClusterMemberCompareObject.id)); Edge node members: $($srcEdgeClusterMemberCompareObject.members.count).`
            Destination Edge Cluster: $($dstEdgeClusterObject.display_name) ($($dstEdgeClusterObject.id)); Edge node members: $($dstEdgeClusterObject.members.count).`
            The destination edge cluster has less member nodes than the source edge cluster. Reallocating this T1 router could have an non-optimal affect on its performance.`
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
# Time to move the T1 routers
# ------------------------------------------------------------------------------

New-DisplayHeading "Re-Allocating Tier 1 Routers"

ForEach ($T1Router in $LogicalTier1RouterToDr) {
    Write-Host -ForegroundColor green "`n Processing Tier 1 Router: $($T1Router.display_name) ($($T1Router.id)) `n"
   
    # retrieve the router link port
    Write-Host "  --> Retrieving Tier1 Router Link Port... "
    $T1RouterLinkPort = Get-LogicalRouterPort -LogicalRouterId $T1Router.id -ResourceType LogicalRouterLinkPortOnTIER1

    # Only need to re-allocate Tier1 routers which are connected to Tier 0 routers
    if (! ( $T1RouterLinkPort) ) {
        Write-Host "`n  --> Re-Allocating Tier1 router: $($T1Router.display_name) ($($T1Router.id))`n   |--> Target Edge Cluster Id: $($dstEdgeClusterObject.id)"
        Invoke-ReAllocateT1Router -LogicalRouterId $T1Router.id -EdgeClusterId $dstEdgeClusterObject.id | Out-Null
    }
    else {
        if ($T1RouterLinkPort.tags) {
            $oldT1RouterLinkPortTags = $T1RouterLinkPort.tags
            Write-Host "  --> Saving tags from old Tier1 Router Link Port: $($T1RouterLinkPort.id)"
        }

        # Delete the Tier1 router link port
        Write-Host "  --> Deleting Tier1 Router Link Port: $($T1RouterLinkPort.id)"
        Remove-LogicalRouterPort -id $T1RouterLinkPort.id

        # Retrieve the linked router port on the Tier0 router
        Write-Host "  --> Retrieving Tier0 Router Link Port: $($T1RouterLinkPort.linked_logical_router_port_id.target_id)"
        $T0RouterLinkPort = Get-LogicalRouterPort -LogicalRouterPortId $T1RouterLinkPort.linked_logical_router_port_id.target_id

        if ($T0RouterLinkPort) {
            if ($T0RouterLinkPort.tags) {
                # Backup any tags on the Tier0 router link port
                $oldT0RouterLinkPortTags = $T0RouterLinkPort.tags
            }

            # Delete the Tier0 router link port
            Write-Host "  --> Deleting Tier0 Router Link Port: $($T0RouterLinkPort.id)"
            Remove-LogicalRouterPort -id $T0RouterLinkPort.id
        }

        # Only Tier1 routers that have services configured (i.e. an edge cluster 
        # assigned) can be re-allocated, otherwise they just need to be disconnected
        # and re-connected to the new tier 0 router.
        if ($T1Router.edge_cluster_id) {
            Write-Host "  --> Re-Allocating Tier1 router: $($T1Router.display_name) ($($T1Router.id))`n   |--> Target Edge Cluster Id: $($dstEdgeClusterObject.id)"
            Invoke-ReAllocateT1Router -LogicalRouterId $T1Router.id -EdgeClusterId $dstEdgeClusterObject.id | Out-Null
        }

        # Create Tier0 router link port on new Tier0 router
        Write-Host "  --> Create new router link port on new Tier 0 router"
        $LogicalRouterLinkPortOnTIER0Splat = @{
            "ResourceType"    = "LogicalRouterLinkPortOnTIER0";
            "LogicalRouterId" = $DstTier0LogicalRouter.id;
            "Description"     = $T0RouterLinkPort.description;
            "DisplayName"     = $T0RouterLinkPort.display_name;
        }
        if ($oldT0RouterLinkPortTags) {
            $LogicalRouterLinkPortOnTIER0Splat.Add("tags", $oldT0RouterLinkPortTags)
        }
        $NewT0RouterLinkPort = New-LogicalRouterLinkPort @LogicalRouterLinkPortOnTIER0Splat
        
        # Create Tier1 router link port on Tier1 routerand pass link target_id of the Tier0 link port
        Write-Host "  --> Create new router link port on Tier 1 router"
        $LogicalRouterLinkPortOnTIER1Splat = @{
            "ResourceType"              = "LogicalRouterLinkPortOnTIER1";
            "LogicalRouterId"           = $T1Router.id;
            "Description"               = $T1RouterLinkPort.description;
            "DisplayName"               = $T1RouterLinkPort.display_name;
            "LinkedLoficalRouterPortId" = $NewT0RouterLinkPort.id;
        }
        if ($oldT1RouterLinkPortTags) {
            $LogicalRouterLinkPortOnTIER1Splat.Add("tags", $oldT1RouterLinkPortTags)
        }
        $NewT1RouterLinkPort = New-LogicalRouterLinkPort @LogicalRouterLinkPortOnTIER1Splat

    }
    Get-Variable -Name oldT1RouterLinkPortTags -ErrorAction 'Ignore' | Remove-Variable -Confirm:$False
    Get-Variable -Name oldT0RouterLinkPortTags -ErrorAction 'Ignore' | Remove-Variable -Confirm:$False
}

$time = $((Get-Date) - $start)
New-DisplayHeading "Script runtime: $($time.Hours):$($time.Minutes):$($Time.Seconds)"

