function Disable-SslVerification {
    if (-not ([System.Management.Automation.PSTypeName]"TrustEverything").Type) {
        Add-Type -TypeDefinition  @"
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class TrustEverything {
    private static bool ValidationCallback(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) {
            return true;
        }
    public static void SetCallback() {
        System.Net.ServicePointManager.ServerCertificateValidationCallback = ValidationCallback;
    }
    public static void UnsetCallback() {
        System.Net.ServicePointManager.ServerCertificateValidationCallback = null;
    }
}
"@}
    [TrustEverything]::SetCallback()
}

Disable-SslVerification
# Prevent 417 "Expectation Failed" Error
[System.Net.ServicePointManager]::Expect100Continue = $false

function New-SubscribedContentLibrary {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Organization:  VMware
    Blog:          www.virtuallyghetto.com
    Twitter:       @lamw
    ===========================================================================
    .DESCRIPTION
        This function creates a new Subscriber Content Library from Subscription URL
    .PARAMETER LibraryName
        The name of the new vSphere Content Library
    .PARAMETER DatastoreName
        The name of the vSphere Datastore to store the Content Library
    .PARAMETER SubscriptionURL
        The URL of the published Content Library
    .PARAMETER SubscriptionThumbprint
        The SSL Thumbprint for the published Content Library
    .PARAMETER OnDemand
        Specifies whether content is downloaded on-demand (e.g. no immediately)
    .PARAMETER AutomaticSync
        Specifies whether automatic synchronization with the external content library is enabled
    .EXAMPLE
        New-SubscribedContentLibrary -LibraryName NestedESXi -DatastoreName vsanDatastore -SubscriptionURL https://download3.vmware.com/software/vmw-tools/lib.json -SubscriptionThumbprint "7a:c4:08:2d:d3:55:56:af:9f:26:43:65:d0:31:99:0b:d2:f3:d8:69" -AutomaticSync
    .EXAMPLE
        New-SubscribedContentLibrary -LibraryName NestedESXi -DatastoreName vsanDatastore -SubscriptionURL https://download3.vmware.com/software/vmw-tools/lib.json -SubscriptionThumbprint "7a:c4:08:2d:d3:55:56:af:9f:26:43:65:d0:31:99:0b:d2:f3:d8:69" -OnDemand
#>
    param(
        [Parameter(Mandatory=$true)][String]$LibraryName,
        [Parameter(Mandatory=$true)][String]$DatastoreName,
        [Parameter(Mandatory=$true)][String]$SubscriptionURL,
        [Parameter(Mandatory=$true)][String]$SubscriptionThumbprint,
        [Parameter(Mandatory=$false)][Switch]$OnDemand,
        [Parameter(Mandatory=$false)][Switch]$AutomaticSync
    )

    $datastore = Get-Datastore -Name $DatastoreName

    if($datastore) {
        $datastoreId = $datastore.ExtensionData.MoRef.Value
        $subscribeLibraryService = Get-CisService -Name "com.vmware.content.subscribed_library"

        $StorageSpec = [pscustomobject] @{
                        datastore_id = $datastoreId;
                        type         = "DATASTORE";
        }

        $UniqueChangeId = [guid]::NewGuid().tostring()

        $createSpec = $subscribeLibraryService.help.create.create_spec.create()
        $createSpec.name = $LibraryName
        $createSpec.type = "SUBSCRIBED"
        $createSpec.storage_backings.Add($StorageSpec)

        if($OnDemand) { $OnDemandFlag = $true } else { $OnDemandFlag = $false }
        if($AutomaticSync) { $AutomaticSyncFlag = $true } else { $AutomaticSyncFlag = $false }
        $createSpec.subscription_info.on_demand = $OnDemandFlag
        $createSpec.subscription_info.automatic_sync_enabled = $AutomaticSyncFlag
        $createSpec.subscription_info.subscription_url = $SubscriptionURL
        $createSpec.subscription_info.authentication_method = "NONE"
        $createSpec.subscription_info.ssl_thumbprint = $SubscriptionThumbprint

        Write-Host "Creating new Subscribed Content Library called $LibraryName ..."
        $subscribeLibraryService.create($UniqueChangeId, $createSpec)
    }
}


## Configurations Section

# Check If deployment passwords are not set in the environment variable
if (-not (Get-Item -Path Env:SHORT_DEPLOYMENT_PASSWORD -ErrorAction SilentlyContinue)) {
    Write-Host "Env:SHORT_DEPLOYMENT_PASSWORD environment variable was not found. Using default value `"Qwer!234`".."
    $Env:SHORT_DEPLOYMENT_PASSWORD = "Qwer!234"
}
if (-not (Get-Item -Path Env:LONG_DEPLOYMENT_PASSWORD -ErrorAction SilentlyContinue)) {
    Write-Host "Env:LONG_DEPLOYMENT_PASSWORD environment variable was not found. Using default value `"Qwer!234Qwer!234`".."
    $Env:LONG_DEPLOYMENT_PASSWORD = "Qwer!234Qwer!234"
}

# Configure directories
$ScriptDir = "D:\Tools\Lab-Deployment"
$PackerDir = Join-Path -Path $ScriptDir -ChildPath "Packer"
$ISODir = Join-Path -Path $ScriptDir -ChildPath "ISOs"
$OVADir = Join-Path -Path $ScriptDir -ChildPath "OVAs"
$TMPDir = Join-Path -Path $ScriptDir -ChildPath "TMP"

# BaseSite(Physical Infrastructure) Configurations
$BaseSiteConfig = @{
    Common = @{
        siteprefix = "Lab"
        netmask = "255.255.255.0"
        gateway = "192.168.10.1"
        dns = @("192.168.10.3", "1.1.1.1")
        ntp = @("0.kr.pool.ntp.org", "1.kr.pool.ntp.org", "2.kr.pool.ntp.org")
        domain = "rainpole.lab"
        domainnetbiosname = "RAINPOLE"
        domaintype = "Forest"
    }
    ESXi = @{
        "Common" = @{
            username = "root"
            password = $Env:SHORT_DEPLOYMENT_PASSWORD
            VMHostAdvancedSettings = @{
                "UserVars.SuppressHyperthreadWarning" = 1
                "UserVars.SuppressShellWarning" = 1
                "UserVars.SuppressCoredumpWarning" = 1
                "VSAN.FakeSCSIReservations" = 1
            }
       }
        "Host" = @(
            @{
                hostname = "esxi01"
                ipaddress = "192.168.10.11"
                localdiskfilter = "*TAMMUZ*"
                localdatastorename = "TAMMUZ-01"
            }
            @{
                hostname = "esxi02"
                ipaddress = "192.168.10.12"
                localdiskfilter = "*TAMMUZ*"
                localdatastorename = "TAMMUZ-02"
            }
            @{
                hostname = "esxi03"
                ipaddress = "192.168.10.13"
                localdiskfilter = "*TAMMUZ*"
                localdatastorename = "TAMMUZ-03"
            }
        )
    }
    VDS = @{
        "Switch" = @{
            Name = "DSwitch"
            Mtu = 9000
            NumUplinkPorts = 4
            UplinkPortName = @("vmnic0", "vmnic1", "vmnic6", "vmnic7")
        }
        "Portgroups" = @{
            "Management" = @{
                Name = "Lab-Management"
                VlanId = 10
                UplinksActive = @("vmnic0", "vmnic1")
                UplinksUnused = @("vmnic6", "vmnic7")
            }
            "vMotion" = @{
                Name = "Lab-vMotion"
                VlanId = 20
                UplinksActive = @("vmnic6", "vmnic7")
                UplinksUnused = @("vmnic0", "vmnic1")
            }
            "vSAN" = @{
                Name = "Lab-vSAN"
                VlanId = 30
                UplinksActive = @("vmnic6", "vmnic7")
                UplinksUnused = @("vmnic0", "vmnic1")
            }
            "vSANFS" = @{
                Name = "Lab-vSANFS"
                VlanId = 31
                UplinksActive = @("vmnic6", "vmnic7")
                UplinksUnused = @("vmnic0", "vmnic1")
            }
            "Nested-10Gb" = @{
                Name = "Nested-10Gb"
                VlanId = $null
                UplinksActive = @("vmnic6", "vmnic7")
                UplinksUnused = @("vmnic0", "vmnic1")
            }
            "Nested-1Gb" = @{
                Name = "Nested-1Gb"
                VlanId = $null
                UplinksActive = @("vmnic0", "vmnic1")
                UplinksUnused = @("vmnic6", "vmnic7")
            }
            "SiteA-Management" = @{
                Name = "SiteA-Management"
                VlanId = 110
                UplinksActive = @("vmnic0", "vmnic1")
                UplinksUnused = @("vmnic6", "vmnic7")
            }
            "SiteB-Management" = @{
                Name = "SiteB-Management"
                VlanId = 210
                UplinksActive = @("vmnic0", "vmnic1")
                UplinksUnused = @("vmnic6", "vmnic7")
            }
            "Lab-Workload" = @{
                Name = "Lab-Workload"
                VlanId = 11
                UplinksActive = @("vmnic0", "vmnic1")
                UplinksUnused = @("vmnic6", "vmnic7")
            }
            "Lab-Frontend" = @{
                Name = "Lab-Frontend"
                VlanId = 12
                UplinksActive = @("vmnic0", "vmnic1")
                UplinksUnused = @("vmnic6", "vmnic7")
            }
        }
    }
    vSAN = @{
        Common = @{
            cachedisksfilter = "INTEL*"
            capacitydisksfilter = "ADATA*"
            vmk_ip_prefix = "192.168.30."
            vmk_netmask = "255.255.255.0"
        }
        Cluster = @{
            datastorename = "vsanDatastore"
            creationtype = "allFlash"
            compressionenabled = $true
            dedupenabled = $true
            performanceserviceenabled = $true
            objectrepairtimerminutes = 999999999
            guesttrimunmap = $true
            addsilenthealthcheck = @("controlleronhcl", "vsanenablesupportinsight", "vumconfig")
        }
        FileService = @{
            vmk_ip_prefix = "192.168.31."
            netmask = "255.255.255.0"
            gateway = "192.168.31.1"
            primarynode = "vsanfs01"
            fsdomain = "default"
            fileshare = @("VSANFS-SiteA", "VSANFS-SiteB")
        }
    }
    VM = @{
        DC = @{
            hostname = "dc01"
            ipaddress = "192.168.10.3"
            dns = @("1.1.1.1", "8.8.8.8")
            username = "Administrator"
            password = $Env:SHORT_DEPLOYMENT_PASSWORD
            dnsrecords = @(
                @{ category = "vcenter"; hostname = "vc01"; ipaddress = "192.168.10.10" }
                @{ category = "esxi"; hostname = "esxi01"; ipaddress = "192.168.10.11" }
                @{ category = "esxi"; hostname = "esxi02"; ipaddress = "192.168.10.12" }
                @{ category = "esxi"; hostname = "esxi03"; ipaddress = "192.168.10.13" }
                @{ category = "vsanfs"; hostname = "vsanfs01"; ipaddress = "192.168.31.111" }
                @{ category = "vsanfs"; hostname = "vsanfs02"; ipaddress = "192.168.31.112" }
                @{ category = "vsanfs"; hostname = "vsanfs03"; ipaddress = "192.168.31.113" }
            )
            additionalzones = @("192.168.31.0/24")
        }
    }
}
$BaseSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.Common.dcname = $($SiteConfig.Common.siteprefix + "-Datacenter")
    $SiteConfig.Common.clustername = $($SiteConfig.Common.siteprefix + "-Cluster")
    $SiteConfig.ESXi.Host | ForEach-Object {
        $_.fqdn = $($_.hostname + "." + $SiteConfig.Common.domain)
    }
    $SiteConfig.VM.DC.vmname = $($SiteConfig.VM.DC.hostname + "." + $SiteConfig.Common.domain)
    $SiteConfig.VM.DC.portgroup = $SiteConfig.VDS.Portgroups.Management.Name
}

# NestedSite(Virtual/Nested Infrastructure) Configurations
$NestedSiteConfig = @()
$NestedSiteConfig += @{
    Common = @{
        siteprefix = "SiteA"
        netmask = "255.255.255.0"
        gateway = "192.168.110.1"
        dns = @("192.168.110.3", "1.1.1.1")
        ntp = @("0.kr.pool.ntp.org", "1.kr.pool.ntp.org", "2.kr.pool.ntp.org")
        parentdomain = "rainpole.lab"
        domain = "sfo01.rainpole.lab"
        domainnetbiosname = "SFO01"
        domaintype = "ChildDomain"
    }
    ESXi = @{
        "Common" = @{
            username = "root"
            password = $Env:SHORT_DEPLOYMENT_PASSWORD
            numcpu = 4
            memorygb = 16
            management_vlan = 110
            VMHostAdvancedSettings = @{
                "UserVars.SuppressHyperthreadWarning" = 1
                "UserVars.SuppressShellWarning" = 1
                "UserVars.SuppressCoredumpWarning" = 1
            }
        }
        "Host" = @(
            @{
                hostname = "sfo01m01esxi01"
                ipaddress = "192.168.110.11"
            }
            @{
                hostname = "sfo01m01esxi02"
                ipaddress = "192.168.110.12"
            }
            @{
                hostname = "sfo01m01esxi03"
                ipaddress = "192.168.110.13"
            }
        )
    }
    VDS = @{
        "Switch" = @{
            Name = "DSwitch-SiteA"
            Mtu = 9000
            NumUplinkPorts = 4
            UplinkPortName = @("vmnic0", "vmnic1", "vmnic2", "vmnic3")
        }
        "Portgroups" = @{
            "Management" = @{
                Name = "sfo01-Management"
                VlanId = 110
                UplinksActive = @("vmnic0")
                UplinksStandby = @("vmnic1")
                UplinksUnused = @("vmnic2", "vmnic3")
            }
            "vMotion" = @{
                Name = "sfo01-vMotion"
                VlanId = 120
                UplinksActive = @("vmnic2")
                UplinksStandby = @("vmnic3")
                UplinksUnused = @("vmnic0", "vmnic1")
            }
            "vSANFS" = @{
                Name = "sfo01-vSANFS"
                VlanId = 31
                UplinksActive = @("vmnic2")
                UplinksStandby = @("vmnic3")
                UplinksUnused = @("vmnic0", "vmnic1")
            }
            "Workload" = @{
                Name = "sfo01-Workload"
                VlanId = 111
                UplinksActive = @("vmnic0")
                UplinksStandby = @("vmnic1")
                UplinksUnused = @("vmnic2", "vmnic3")
            }
            "Frontend" = @{
                Name = "sfo01-Frontend"
                VlanId = 112
                UplinksActive = @("vmnic0")
                UplinksStandby = @("vmnic1")
                UplinksUnused = @("vmnic2", "vmnic3")
            }
        }
    }
    VM = @{
        DC = @{
            hostname = "sfo01dc01"
            ipaddress = "192.168.110.3"
            dns = "192.168.10.3"
            username = "Administrator"
            password = $Env:SHORT_DEPLOYMENT_PASSWORD
            dnsrecords = @(
                @{ category = "esxi"; hostname = "sfo01m01esxi01"; ipaddress = "192.168.110.11" }
                @{ category = "esxi"; hostname = "sfo01m01esxi02"; ipaddress = "192.168.110.12" }
                @{ category = "esxi"; hostname = "sfo01m01esxi03"; ipaddress = "192.168.110.13" }
                @{ category = "haproxy"; hostname = "sfo01haproxy01"; ipaddress = "192.168.110.21" }
            )
        }
    }
}
$NestedSiteConfig += @{
    Common = @{
        siteprefix = "SiteB"
        netmask = "255.255.255.0"
        gateway = "192.168.210.1"
        dns = @("192.168.210.3", "1.1.1.1")
        ntp = @("0.kr.pool.ntp.org", "1.kr.pool.ntp.org", "2.kr.pool.ntp.org")
        parentdomain = "rainpole.lab"
        domain = "lax01.rainpole.lab"
        domainnetbiosname = "LAX01"
        domaintype = "ChildDomain"
    }
    ESXi = @{
        "Common" = @{
            username = "root"
            password = $Env:SHORT_DEPLOYMENT_PASSWORD
            numcpu = 4
            memorygb = 16
            management_vlan = 210
            VMHostAdvancedSettings = @{
                "UserVars.SuppressHyperthreadWarning" = 1
                "UserVars.SuppressShellWarning" = 1
                "UserVars.SuppressCoredumpWarning" = 1
            }
        }
        "Host" = @(
            @{
                hostname = "lax01m01esxi01"
                ipaddress = "192.168.210.11"
            }
            @{
                hostname = "lax01m01esxi02"
                ipaddress = "192.168.210.12"
            }
            @{
                hostname = "lax01m01esxi03"
                ipaddress = "192.168.210.13"
            }
        )
    }
    VDS = @{
        "Switch" = @{
            Name = "DSwitch-SiteB"
            Mtu = 9000
            NumUplinkPorts = 4
            UplinkPortName = @("vmnic0", "vmnic1", "vmnic2", "vmnic3")
        }
        "Portgroups" = @{
            "Management" = @{
                Name = "lax01-Management"
                VlanId = 210
                UplinksActive = @("vmnic0")
                UplinksStandby = @("vmnic1")
                UplinksUnused = @("vmnic2", "vmnic3")
            }
            "vMotion" = @{
                Name = "lax01-vMotion"
                VlanId = 220
                UplinksActive = @("vmnic2")
                UplinksStandby = @("vmnic3")
                UplinksUnused = @("vmnic0", "vmnic1")
            }
            "vSANFS" = @{
                Name = "lax01-vSANFS"
                VlanId = 31
                UplinksActive = @("vmnic2")
                UplinksStandby = @("vmnic3")
                UplinksUnused = @("vmnic0", "vmnic1")
            }
            "Workload" = @{
                Name = "lax01-Workload"
                VlanId = 211
                UplinksActive = @("vmnic0")
                UplinksStandby = @("vmnic1")
                UplinksUnused = @("vmnic2", "vmnic3")
            }
            "Frontend" = @{
                Name = "lax01-Frontend"
                VlanId = 212
                UplinksActive = @("vmnic0")
                UplinksStandby = @("vmnic1")
                UplinksUnused = @("vmnic2", "vmnic3")
            }
        }
    }
    VM = @{
        DC = @{
            hostname = "lax01dc01"
            ipaddress = "192.168.210.3"
            dns = "192.168.10.3"
            username = "Administrator"
            password = $Env:SHORT_DEPLOYMENT_PASSWORD
            dnsrecords = @(
                @{ category = "esxi"; hostname = "lax01m01esxi01"; ipaddress = "192.168.210.11" }
                @{ category = "esxi"; hostname = "lax01m01esxi02"; ipaddress = "192.168.210.12" }
                @{ category = "esxi"; hostname = "lax01m01esxi03"; ipaddress = "192.168.210.13" }
                @{ category = "haproxy"; hostname = "lax01haproxy01"; ipaddress = "192.168.210.21" }
            )
        }
    }
}
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.Common.clustername = $($SiteConfig.Common.siteprefix + "-Cluster")
    $SiteConfig.Common.resourcepoolname = $($SiteConfig.Common.siteprefix + " Resource Pool")
    $SiteConfig.Common.datastorename = $("VSANFS" + "-" + $SiteConfig.Common.siteprefix)
    $SiteConfig.ESXi.Host | ForEach-Object {
        $_.fqdn = $($_.hostname + "." + $SiteConfig.Common.domain)
    }
    $SiteConfig.VM.DC.vmname = $($SiteConfig.VM.DC.hostname + "." + $SiteConfig.Common.domain)
    $SiteConfig.VM.DC.portgroup = $BaseSiteConfig.VDS.Portgroups.$($SiteConfig.Common.siteprefix + "-Management").Name
}

# VM Deployment Configurations
$VMDeploymentConfig = @{
    Dnsmasq = @{
        PackerWorkingDir = Join-Path -Path $PackerDir -ChildPath "Linux"
        PackerJsonFilename = "centos8.json"
        PackerJsonTmpFilename = "dnsmasq.json"
        builders = @{
            vm_name = "dnsmasq" + "." + $BaseSiteConfig.Common.domain
            iso_url = Join-Path -Path $ISODir -ChildPath "CentOS-8.2.2004-x86_64-dvd1.iso"
            remote_host = $BaseSiteConfig.ESXi.Host[0].ipaddress
            remote_username = $BaseSiteConfig.ESXi.Common.username
            remote_password = $BaseSiteConfig.ESXi.Common.password
            remote_datastore = $BaseSiteConfig.ESXi.Host[0].localdatastorename
            ssh_host = "192.168.10.9"
            ssh_password = "packer"
            ssh_username = "packer"
        }
        provisioners = @{
            playbook_file = "scripts/dnsmasq.yml"
            extra_arguments = "`\`"setupdns=true`\`""
        }
    }
    VCSA = @{
        VCSAWorkingDir = "E:\vcsa-cli-installer\win32"
        VCSAJsonFilename = "E:\vcsa-cli-installer\templates\install\embedded_vCSA_on_ESXi.json"
        VCSAJsonTmpFilename = "vcsa_deployment.json"
        Appliance = @{
            size = "small"
            is_thin = $true
            fqdn = "vc01.rainpole.lab"
            ipaddress = "192.168.10.10"
            netmask = "24"
            gateway = "192.168.10.1"
            dns = @("192.168.10.9", "1.1.1.1")
            ntp = @("0.kr.pool.ntp.org", "1.kr.pool.ntp.org", "2.kr.pool.ntp.org")
            ssh_enable = $true
            username = "root"
            password = $Env:SHORT_DEPLOYMENT_PASSWORD
            ssodomain = "vsphere.lab"
            ssousername = "Administrator"
            ssopassword = $Env:SHORT_DEPLOYMENT_PASSWORD
            ceip_enabled = $false
        }
    }
    HAProxy = @{
        OVAFilename = Join-Path -Path $OVADir -ChildPath "haproxy-v0.2.0.ova"
        appliance_permit_root_login = $true
        appliance_root_pwd = $Env:SHORT_DEPLOYMENT_PASSWORD
        DeploymentOption = "frontend"
        NetworkMapping_Management = "Lab-Management"
        NetworkMapping_Workload = "Lab-Workload"
        NetworkMapping_Frontend = "Lab-Frontend"
        network_hostname = "haproxy01.rainpole.lab"
        network_nameservers = "192.168.10.9"
        network_management_ip = "192.168.10.21/24"
        network_management_gateway = "192.168.10.1"
        network_workload_ip = "192.168.11.2/24"
        network_workload_gateway = "192.168.11.1"
        network_frontend_ip = "192.168.12.2/24"
        network_frontend_gateway = "192.168.12.1"
        loadbalance_haproxy_user = "admin"
        loadbalance_haproxy_pwd = $Env:SHORT_DEPLOYMENT_PASSWORD
        loadbalance_service_ip_range = "192.168.12.128/25"
        vm_Name = "haproxy01.rainpole.lab"
        vm_Location = "Lab-Cluster"
        vm_VMHost = "esxi02.rainpole.lab"
        vm_Datastore = "vsanDatastore"
        vm_DiskStorageFormat = "thin"
    }
    NSXManager = @{
        OVAFilename = Join-Path -Path $OVADir -ChildPath "nsx-unified-appliance-3.1.3.0.0.18329005.ova"
        DeploymentOption = "medium"
        IpProtocol = "IPv4"
        Network_1 = "Lab-Management"
        nsx_passwd_0 = $Env:LONG_DEPLOYMENT_PASSWORD
        nsx_cli_passwd_0 = $Env:LONG_DEPLOYMENT_PASSWORD
        nsx_cli_audit_passwd_0 = $Env:LONG_DEPLOYMENT_PASSWORD
        nsx_cli_username = "admin"
        nsx_cli_audit_username = "audit"
        extraPara = $Env:LONG_DEPLOYMENT_PASSWORD
        nsx_hostname = "nsxmgr01.rainpole.lab"
        nsx_role = "NSX Manager"
        nsx_ip_0 = "192.168.10.51"
        nsx_netmask_0 = "255.255.255.0"
        nsx_gateway_0 = "192.168.10.1"
        nsx_dns1_0 = "192.168.10.9"
        nsx_domain_0 = "rainpole.lab"
        nsx_ntp_0 = "0.kr.pool.ntp.org 1.kr.pool.ntp.org 2.kr.pool.ntp.org"
        nsx_isSSHEnabled = $true
        nsx_allowSSHRootLogin = $true
        nsx_swIntegrityCheck = $false
        vm_Location = "Lab-Cluster"
        vm_VMHost = "esxi01.rainpole.lab"
        vm_Datastore = "vsanDatastore"
        vm_DiskStorageFormat = "thin"
    }
    WindowsTemplate = @{
        PackerWorkingDir = Join-Path -Path $PackerDir -ChildPath "Windows"
        PackerJsonFilename = "windows2019.json"
        PackerJsonTmpFilename = "windows2019tmp.json"
        builders = @{
            datacenter = $BaseSiteConfig.Common.dcname
            cluster = $BaseSiteConfig.Common.clustername
            datastore = $BaseSiteConfig.vSAN.Cluster.datastorename
            vm_name = "dnsmasq" + "." + $BaseSiteConfig.Common.domain
            winrm_username = "Administrator"
            winrm_password = $Env:SHORT_DEPLOYMENT_PASSWORD
        }
        provisioners = @{
            elevated_user = "Administrator"
            elevated_password = $Env:SHORT_DEPLOYMENT_PASSWORD
        }
    }
    ESXiTemplate = @{
        OVFName = "Nested_ESXi7.0u2_Appliance_Template_v1.0"
    }
}
$VMDeploymentConfig.VCSA.Appliance.ssoaccount = $VMDeploymentConfig.VCSA.Appliance.ssousername + "@" + $VMDeploymentConfig.VCSA.Appliance.ssodomain
$VMDeploymentConfig.VCSA.Appliance.vmname = $VMDeploymentConfig.VCSA.Appliance.fqdn
$VMDeploymentConfig.WindowsTemplate.builders.vcenter_server = $VMDeploymentConfig.VCSA.Appliance.fqdn
$VMDeploymentConfig.WindowsTemplate.builders.username = $VMDeploymentConfig.VCSA.Appliance.ssoaccount
$VMDeploymentConfig.WindowsTemplate.builders.password = $VMDeploymentConfig.VCSA.Appliance.password

$LicenseKey = Get-Content license_keys.txt | ConvertFrom-StringData

# Content Library Configurations
$ContentLibraries = @(
    @{
        LibraryName = "vghetto-nestedesxi"
        DatastoreName = $BaseSiteConfig.vSAN.Cluster.datastorename
        SubscriptionUrl = "https://download3.vmware.com/software/vmw-tools/lib.json"
        SubscriptionThumbprint = "01:8d:fd:13:a6:9e:ca:ac:cb:7c:67:18:c1:47:11:8c:64:91:5d:c9"
        AutomaticSync = $true
    },
    @{
        LibraryName = "tkg-cl"
        DatastoreName = $BaseSiteConfig.vSAN.Cluster.datastorename
        SubscriptionUrl = "https://wp-content.vmware.com/v2/latest/lib.json"
        SubscriptionThumbprint = "01:8d:fd:13:a6:9e:ca:ac:cb:7c:67:18:c1:47:11:8c:64:91:5d:c9"
        AutomaticSync = $true
    },
    @{
        LibraryName = "VM Service Image for CentOS"
        DatastoreName = $BaseSiteConfig.vSAN.Cluster.datastorename
        SubscriptionUrl = "https://s3.us-west-2.amazonaws.com/cspmarketplacemainbuck/marketplace-product-files/lib_28bd2b65-aff7-44b9-a5e6-5ea7a27a2a7d_bec4d0d8-e793-431b-a3d5-7fc90386bc6f.json"
        SubscriptionThumbprint = "4b:7c:8d:f8:41:ce:17:1f:b2:37:20:9a:eb:0e:d9:9d:6d:e5:43:c1"
        AutomaticSync = $true
    },
    @{
        Name = "haproxy"
        Datastore = $BaseSiteConfig.vSAN.Cluster.datastorename
    }
)
$ContentLibraryItems = @(
    @{
        ContentLibrary = "haproxy"
        Name = "haproxy-v0.1.10"
        Uri = "https://cdn.haproxy.com/download/haproxy/vsphere/ova/haproxy-v0.1.10.ova"
        FileName = "haproxy-v0.1.10.ova"
        SslThumbprint = "fa:d3:52:ee:5d:7a:1a:47:3a:38:f1:34:91:df:c1:53:64:bd:88:4a"
    },
    @{
        ContentLibrary = "haproxy"
        Name = "haproxy-v0.2.0"
        Files = @((Join-Path -Path $OVADir -ChildPath "haproxy-v0.2.0.ova"))
        DisableOvfCertificateChecks = $true
    }
)


## Bootstrap Section (VCSA with vSAN)

$FirstHostConfig = $BaseSiteConfig.ESXi.Host[0].Clone()
$FirstHostConfig.vsandatastorename = $BaseSiteConfig.vSAN.Cluster.datastorename
$FirstHostConfig.managementvlanid = $BaseSiteConfig.VDS.Portgroups.Management.VlanId
$FirstHostConfig.portgroup = "VM Network"
$HostsToAdd = $BaseSiteConfig.ESXi.Host[1..($BaseSiteConfig.ESXi.Host.Count - 1)]

$CmdletParams = @{
    Server = $FirstHostConfig.fqdn
    User = $BaseSiteConfig.ESXi.Common.username
    Password = $BaseSiteConfig.ESXi.Common.password
}
Connect-VIServer @CmdletParams
if (-not (Get-VirtualPortGroup -Name $FirstHostConfig.portgroup -ErrorAction SilentlyContinue | Set-VirtualPortGroup -VLanId $FirstHostConfig.managementvlanid -ErrorAction SilentlyContinue)) {
    New-VirtualPortGroup -Name $FirstHostConfig.portgroup -VirtualSwitch (Get-VirtualSwitch -Name "vSwitch0") -VLanId $FirstHostConfig.managementvlanid
}
$FirstHost = Get-VMHost $FirstHostConfig.fqdn
$FirstHost | Set-VMHost -State Connected

# Create Local Datastore
$CanonicalName = (Get-ScsiLun $FirstHostConfig.localdiskfilter).CanonicalName
New-Datastore -Name $FirstHostConfig.localdatastorename -Path $CanonicalName -Vmfs

# "esxcli system settings advanced set -o /Net/GuestIPHack -i 1" is required
$PackerWorkingDir = $VMDeploymentConfig.Dnsmasq.PackerWorkingDir
$PackerJsonFilename = Join-Path -Path $PackerWorkingDir -ChildPath $VMDeploymentConfig.Dnsmasq.PackerJsonFilename
$PackerJsonTmpFilename = Join-Path -Path $TMPDir -ChildPath $VMDeploymentConfig.Dnsmasq.PackerJsonTmpFilename
Set-Location $PackerWorkingDir

$DeploymentJsonObject = Get-Content $PackerJsonFilename | Out-String | ConvertFrom-Json
$DeploymentJsonObject.builders[0].vm_name = $VMDeploymentConfig.Dnsmasq.builders.vm_name
$DeploymentJsonObject.builders[0].iso_url = $VMDeploymentConfig.Dnsmasq.builders.iso_url -replace '\\','/'
$FileHash = Get-FileHash -Algorithm SHA1 -Path $VMDeploymentConfig.Dnsmasq.builders.iso_url
$DeploymentJsonObject.builders[0].iso_checksum = $FileHash.Algorithm + ":" + $FileHash.Hash
$DeploymentJsonObject.builders[0].remote_host = $VMDeploymentConfig.Dnsmasq.builders.remote_host
$DeploymentJsonObject.builders[0].remote_username = $VMDeploymentConfig.Dnsmasq.builders.remote_username
$DeploymentJsonObject.builders[0].remote_password = $VMDeploymentConfig.Dnsmasq.builders.remote_password
$DeploymentJsonObject.builders[0].remote_datastore = $VMDeploymentConfig.Dnsmasq.builders.remote_datastore
$DeploymentJsonObject.builders[0].ssh_host = $VMDeploymentConfig.Dnsmasq.builders.ssh_host
$DeploymentJsonObject.builders[0].ssh_password = $VMDeploymentConfig.Dnsmasq.builders.ssh_password
$DeploymentJsonObject.builders[0].ssh_username = $VMDeploymentConfig.Dnsmasq.builders.ssh_username
$ExtraArgs = $DeploymentJsonObject.provisioners | Where-Object type -eq "ansible-local"
$ExtraArgs.playbook_file = $VMDeploymentConfig.Dnsmasq.provisioners.playbook_file
$ExtraArgs.extra_arguments[1] = $VMDeploymentConfig.Dnsmasq.provisioners.extra_arguments
$DeploymentJson = $DeploymentJsonObject | ConvertTo-Json -Depth 5
[System.Text.RegularExpressions.Regex]::Unescape($DeploymentJson) | Out-File -Encoding Ascii -FilePath $PackerJsonTmpFilename
..\packer.exe build $PackerJsonTmpFilename

Start-VM $VMDeploymentConfig.Dnsmasq.builders.vm_name
do {
    if (Test-NetConnection -ComputerName $VMDeploymentConfig.Dnsmasq.builders.ssh_host -InformationLevel Quiet -WarningAction SilentlyContinue) {
        $is_alive = $true
    } else {
        $is_alive = $false
        Start-Sleep -Seconds 5
    }
} while ($is_alive -eq $false)

# Clear partitions on the SSD
$StorageSystemView = Get-View (Get-View $FirstHost).ConfigManager.StorageSystem
$HostDiskPartitionSpec = New-Object VMware.Vim.HostDiskPartitionSpec
Get-ScsiLun -VmHost $FirstHost | Where-Object {($_.IsSsd -eq $true) -and ($_.CanonicalName -NotLike $FirstHostConfig.localdiskfilter)} | ForEach-Object {
    $StorageSystemView.UpdateDiskPartitions($_.ConsoleDeviceName, $HostDiskPartitionSpec)
}

# Enumerate host disks eligible for vSAN
$VsanView = Get-VsanView -Id "VsanVcsaDeployerSystem-vsan-vcsa-deployer-system"
$VsanSystemView = Get-View (Get-View -VIObject $FirstHost).ConfigManager.VsanSystem
$DisksForVsan = $VsanSystemView.QueryDisksForVsan($null) | Where-Object State -eq "eligible"

# Configure VsanDiskMappingCreationSpec
$VsanDiskMappingCreationSpec = New-Object VMware.Vsan.Views.VimVsanHostDiskMappingCreationSpec
$VsanDiskMappingCreationSpec.CacheDisks = $DisksForVsan.Disk | Where-Object Model -like $BaseSiteConfig.vSAN.Common.cachedisksfilter
$VsanDiskMappingCreationSpec.CapacityDisks = $DisksForVsan.Disk | Where-Object Model -like $BaseSiteConfig.vSAN.Common.capacitydisksfilter
$VsanDiskMappingCreationSpec.CreationType = $BaseSiteConfig.vSAN.Cluster.creationtype
$VsanDiskMappingCreationSpec.Host = $FirstHost.Id

# Configure VsanDataEfficiencyConfig
$VsanDataEfficiencyConfig = New-Object VMware.Vsan.Views.VsanDataEfficiencyConfig
$VsanDataEfficiencyConfig.CompressionEnabled = $BaseSiteConfig.vSAN.Cluster.compressionenabled
$VsanDataEfficiencyConfig.DedupEnabled = $BaseSiteConfig.vSAN.Cluster.dedupenabled

# Configure VsanPrepareVsanForVcsaSpec
$VsanPrepareVsanForVcsaSpec = New-Object VMware.Vsan.Views.VsanPrepareVsanForVcsaSpec
$VsanPrepareVsanForVcsaSpec.VsanDiskMappingCreationSpec = $VsanDiskMappingCreationSpec
$VsanPrepareVsanForVcsaSpec.VsanDataEfficiencyConfig = $VsanDataEfficiencyConfig

# Run VsanPrepareVsanForVcsa with VsanPrepareVsanForVcsaSpec
$taskId = $VsanView.VsanPrepareVsanForVcsa($VsanPrepareVsanForVcsaSpec)
Write-Host -NoNewLine "Progress:"
do {
    $ProgressStatus = $VsanView.VsanVcsaGetBootstrapProgress($taskId)
    Write-Host -NoNewLine " $($ProgressStatus.ProgressPct)%"
    Start-Sleep -Seconds 1
} until ($ProgressStatus.Success -eq $true)

# Create VCSA deployment JSON
$DeploymentJsonObject = Get-Content $VMDeploymentConfig.VCSA.VCSAJsonFilename | Out-String | ConvertFrom-Json
$DeploymentJsonObject.new_vcsa.esxi.hostname = $FirstHostConfig.fqdn
$DeploymentJsonObject.new_vcsa.esxi.username = $BaseSiteConfig.ESXi.Common.username
$DeploymentJsonObject.new_vcsa.esxi.password = $BaseSiteConfig.ESXi.Common.password
$DeploymentJsonObject.new_vcsa.esxi.deployment_network = $FirstHostConfig.portgroup
$DeploymentJsonObject.new_vcsa.esxi.datastore = $FirstHostConfig.vsandatastorename
$DeploymentJsonObject.new_vcsa.appliance.thin_disk_mode = $VMDeploymentConfig.VCSA.Appliance.is_thin
$DeploymentJsonObject.new_vcsa.appliance.deployment_option = $VMDeploymentConfig.VCSA.Appliance.size
$DeploymentJsonObject.new_vcsa.appliance.name = $VMDeploymentConfig.VCSA.Appliance.vmname
$DeploymentJsonObject.new_vcsa.network.mode = "static"
$DeploymentJsonObject.new_vcsa.network.system_name = $VMDeploymentConfig.VCSA.Appliance.fqdn
$DeploymentJsonObject.new_vcsa.network.ip = $VMDeploymentConfig.VCSA.Appliance.ipaddress
$DeploymentJsonObject.new_vcsa.network.prefix = $VMDeploymentConfig.VCSA.Appliance.netmask
$DeploymentJsonObject.new_vcsa.network.gateway = $VMDeploymentConfig.VCSA.Appliance.gateway
$DeploymentJsonObject.new_vcsa.network.dns_servers = $VMDeploymentConfig.VCSA.Appliance.dns
$DeploymentJsonObject.new_vcsa.os.password = $VMDeploymentConfig.VCSA.Appliance.password
$DeploymentJsonObject.new_vcsa.os.ntp_servers = $VMDeploymentConfig.VCSA.Appliance.ntp
$DeploymentJsonObject.new_vcsa.os.ssh_enable = $VMDeploymentConfig.VCSA.Appliance.ssh_enable
$DeploymentJsonObject.new_vcsa.sso.password = $VMDeploymentConfig.VCSA.Appliance.ssopassword
$DeploymentJsonObject.new_vcsa.sso.domain_name = $VMDeploymentConfig.VCSA.Appliance.ssodomain
$DeploymentJsonObject.ceip.settings.ceip_enabled = $VMDeploymentConfig.VCSA.Appliance.ceip_enabled
$ovftool_arguments = [PSCustomObject]@{ defaultStorageRawProfile = "((`\`"hostFailuresToTolerate`\`" i1) (`\`"forceProvisioning`\`" i1))" }
$DeploymentJsonObject.new_vcsa | Add-Member -Type NoteProperty -Name "ovftool_arguments" -Value $ovftool_arguments
$DeploymentJson = $DeploymentJsonObject | ConvertTo-Json -Depth 5
$VCSAJsonTmpFilename = Join-Path -Path $TMPDir -ChildPath $VMDeploymentConfig.VCSA.VCSAJsonTmpFilename
[System.Text.RegularExpressions.Regex]::Unescape($DeploymentJson) | Out-File -Encoding Ascii -FilePath $VCSAJsonTmpFilename

# Deploy VCSA using CLI
Set-Location $VMDeploymentConfig.VCSA.VCSAWorkingDir
./vcsa-deploy.exe install --accept-eula --no-ssl-certificate-verification $VCSAJsonTmpFilename

# Change connection from ESXi Host to vCenter Server
Disconnect-VIServer * -Confirm:$false
$CmdletParams = @{
    Server = $VMDeploymentConfig.VCSA.Appliance.fqdn
    User = $VMDeploymentConfig.VCSA.Appliance.ssoaccount
    Password = $VMDeploymentConfig.VCSA.Appliance.ssopassword
}
Connect-VIServer @CmdletParams

# Configure VsanVcPostDeployConfigSpec
$VsanVcPostDeployConfigSpec = New-Object VMware.Vsan.Views.VsanVcPostDeployConfigSpec
$HostConnectSpec = New-Object VMware.Vim.HostConnectSpec
$HostConnectSpec.Force = $true
$HostConnectSpec.HostName = $FirstHostConfig.fqdn
$HostConnectSpec.UserName = $BaseSiteConfig.ESXi.Common.username
$HostConnectSpec.Password = $BaseSiteConfig.ESXi.Common.password
$VsanVcPostDeployConfigSpec.FirstHost = $HostConnectSpec
$VsanVcPostDeployConfigSpec.ClusterName = $BaseSiteConfig.Common.clustername
$VsanVcPostDeployConfigSpec.DcName = $BaseSiteConfig.Common.dcname
$VsanVcPostDeployConfigSpec.VsanDataEfficiencyConfig = $VsanDataEfficiencyConfig
$VsanVcPostDeployConfigSpec.VsanLicenseKey = $LicenseKey.Vsan
$VsanVcPostDeployConfigSpec.HostLicenseKey = $LicenseKey.Host
$VsanView = Get-VsanView -Id "VsanVcsaDeployerSystem-vsan-vcsa-deployer-system"

$VsanVcPostDeployConfigSpec.HostsToAdd = @()
$HostsToAdd | ForEach-Object {
    $HostConnectSpec = New-Object VMware.Vim.HostConnectSpec
    $HostConnectSpec.Force = $true
    $HostConnectSpec.HostName = $_.hostname + "." + $BaseSiteConfig.Common.domain
    $HostConnectSpec.UserName = $BaseSiteConfig.ESXi.Common.username
    $HostConnectSpec.Password = $BaseSiteConfig.ESXi.Common.password
    $VsanVcPostDeployConfigSpec.HostsToAdd += $HostConnectSpec
}

# Run VsanPostConfigForVcsa with VsanVcPostDeployConfigSpec
$taskId = $VsanView.VsanPostConfigForVcsa($VsanVcPostDeployConfigSpec)
do {
    $ProgressStatus = $VsanView.VsanVcsaGetBootstrapProgress($taskId)
    Write-Host -NoNewLine " $($ProgressStatus.ProgressPct)%"
    Start-Sleep -Seconds 1
} until ($ProgressStatus.Success -eq $true)


## Customization Section

# Set Management portgroup uplink redundant
$VMHosts = Get-VMHost
$VMHostsToAdd = $VMHosts[1..($VMHosts.Count - 1)]

$VMHosts | ForEach-Object {
    $PhysicalNIC = Get-VMHostNetworkAdapter -VMHost $_ -Physical -Name "vmnic1"
    $VirtualSwitch = Get-VirtualSwitch -VMHost $_ -Name "vSwitch0"
    Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $VirtualSwitch -VMHostPhysicalNic $PhysicalNIC -Confirm:$false
    $VirtualPortGroup = Get-VirtualPortGroup -VMHost $_ -Name "Management Network"
    $Policy = Get-NicTeamingPolicy -VirtualPortGroup $VirtualPortGroup
    Set-NicTeamingPolicy -VirtualPortGroupPolicy $Policy -InheritFailoverOrder:$true -Confirm:$false
}

# Create vDS
if (-not ($VDSwitch = Get-VDSwitch $BaseSiteConfig.VDS.Switch.Name -ErrorAction SilentlyContinue)) {
    $CmdletParams = @{
        Location = Get-Datacenter $BaseSiteConfig.Common.dcname
        Mtu = $BaseSiteConfig.VDS.Switch.Mtu
        Name = $BaseSiteConfig.VDS.Switch.Name
        NumUplinkPorts = $BaseSiteConfig.VDS.Switch.NumUplinkPorts
        Confirm = $false
    }
    $VDSwitch = New-VDSwitch @CmdletParams
}

$DVSConfigSpec = New-Object VMware.Vim.DVSConfigSpec
$DVSConfigSpec.ConfigVersion = $VDSwitch.ExtensionData.Config.ConfigVersion

# Change uplink name
$DVSUplinkPortPolicy = New-Object VMware.Vim.DVSNameArrayUplinkPortPolicy
$DVSUplinkPortPolicy.UplinkPortName = $BaseSiteConfig.VDS.Switch.UplinkPortName
$DVSConfigSpec.UplinkPortPolicy = $DVSUplinkPortPolicy
# Enable MacLearning
$DVSConfigSpec.DefaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
$DVSConfigSpec.DefaultPortConfig.MacManagementPolicy = New-Object VMware.Vim.DVSMacManagementPolicy
$DVSConfigSpec.DefaultPortConfig.MacManagementPolicy.ForgedTransmits = $True
$DVSConfigSpec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy = New-Object VMware.Vim.DVSMacLearningPolicy
$DVSConfigSpec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.Enabled = $True
$DVSConfigSpec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.AllowUnicastFlooding = $True
$DVSConfigSpec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.Limit = 4000
$DVSConfigSpec.DefaultPortConfig.MacManagementPolicy.MacLearningPolicy.LimitPolicy = "DROP"

$VDSwitch.ExtensionData.ReconfigureDvs($DVSConfigSpec)

# Create vDPortGroups
$BaseSiteConfig.VDS.Portgroups.GetEnumerator() | ForEach-Object {
    $PGName = $_.Value.Name
    $VDPortgroup = Get-VDPortgroup -VDSwitch $VDSwitch -Name $PGName -ErrorAction SilentlyContinue
    if (-not $VDPortgroup) {
        Write-Host -NoNewline "Creating VDPortgroup $($PGName).."
        if ($_.Value.VlanId) {
            $VDPortgroup = New-VDPortgroup -VDSwitch $VDSwitch -Name $PGName -VlanId $_.Value.VlanId
        } else {
            $VDPortgroup = New-VDPortgroup -VDSwitch $VDSwitch -Name $PGName -VlanTrunkRange "0-4094"
        }
        Write-Host -ForegroundColor Green "OK"
    }
    $CmdletParams = @{
        Confirm = $false
    }
    if ($_.Value.UplinksActive) { $CmdletParams.ActiveUplinkPort = $_.Value.UplinksActive }
    if ($_.Value.UplinksStandby) { $CmdletParams.StandbyUplinkPort = $_.Value.UplinksStandby }
    if ($_.Value.UplinksUnused) { $CmdletParams.UnusedUplinkPort = $_.Value.UplinksUnused }

    Get-VDUplinkTeamingPolicy -VDPortgroup $VDPortgroup | Set-VDUplinkTeamingPolicy @CmdletParams | Out-Null
}

# Add VMHosts to VDSwitch and migrate vNICs into VDSwitch
$VMHosts | ForEach-Object {
    Add-VDSwitchVMHost -VDSwitch $VDSwitch -VMHost $_
    $PhysicalNIC = Get-VMHostNetworkAdapter -VMHost $_ -Physical -Name "vmnic0"
    $VirtualNIC = Get-VMHostNetworkAdapter -VMHost $_ -Name "vmk0"
    Remove-VirtualSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter $PhysicalNIC -Confirm:$false
    $CmdletParams = @{
        DistributedSwitch = $VDSwitch
        VMHostPhysicalNic = $PhysicalNIC
        VMHostVirtualNic = $VirtualNic
        VirtualNicPortgroup = $BaseSiteConfig.VDS.Portgroups.Management.Name
        Confirm = $false
    }
    Add-VDSwitchPhysicalNetworkAdapter @CmdletParams
}
Get-NetworkAdapter * | Set-NetworkAdapter -Portgroup $BaseSiteConfig.VDS.Portgroups.Management.Name -Confirm:$false
$VMHosts | ForEach-Object {
    Get-VMHostNetworkAdapter -VMHost $_ -Physical -Name $BaseSiteConfig.VDS.Switch.UplinkPortName | ForEach-Object {
       Add-VDSwitchPhysicalNetworkAdapter -DistributedSwitch $VDSwitch -VMHostPhysicalNic $_ -Confirm:$false -ErrorAction SilentlyContinue
    }
}
Get-VirtualSwitch -Standard | Remove-VirtualSwitch -Confirm:$false

# Create vmk ports for vMotion(DHCP), vSAN(fixed IP)
$VMHosts | ForEach-Object {
    $VMHostNetworkStack = Get-VMHostNetworkStack -VMHost $_ | Where-Object Id -eq vmotion
    $CmdletParams = @{
        VMHost = $_
        Mtu = 9000
        VirtualSwitch = $VDSwitch
        PortGroup = $BaseSiteConfig.VDS.Portgroups.vMotion.Name
        NetworkStack = $VMHostNetworkStack
    }
    New-VMHostNetworkAdapter @CmdletParams
    $CmdletParams = @{
        VMHost = $_
        Mtu = 9000
        VirtualSwitch = $VDSwitch
        PortGroup = $BaseSiteConfig.VDS.Portgroups.vSAN.Name
        IP = $BaseSiteConfig.vSAN.Common.vmk_ip_prefix + ((Get-VMHostNetworkAdapter -VMHost $_ -Name "vmk0").IP -split "\.")[3]
        SubnetMask = $BaseSiteConfig.vSAN.Common.vmk_netmask
        VsanTrafficEnabled = $true
    }
    New-VMHostNetworkAdapter @CmdletParams
}

# Create Local Datastore
$HostsToAdd | ForEach-Object {
    $CanonicalName = (Get-ScsiLun -VmHost $_.fqdn $_.localdiskfilter).CanonicalName
    New-Datastore -VmHost $_.fqdn -Name $_.localdatastorename -Path $CanonicalName -Vmfs
}

# Clear partitions on the SSD
$VMHostsToAdd | ForEach-Object {
    $_ | Set-VMHost -State Connected
    $StorageSystemView = Get-View (Get-View $_).ConfigManager.StorageSystem
    $HostDiskPartitionSpec = New-Object VMware.Vim.HostDiskPartitionSpec
    Get-ScsiLun -VmHost $_ | Where-Object {($_.IsSsd -eq $true) -and ($_.CanonicalName -NotLike $FirstHostConfig.localdiskfilter)} | ForEach-Object {
        $StorageSystemView.UpdateDiskPartitions($_.ConsoleDeviceName, $HostDiskPartitionSpec)
    }
}

# Add DiskGroup on the remaining hosts
$VMHostsToAdd | ForEach-Object {
    $DisksForVsan = Get-ScsiLun -VmHost $_ | Where-Object VsanStatus -eq Eligible
    $CacheDisks = $DisksForVsan | Where-Object Model -like $BaseSiteConfig.vSAN.Common.cachedisksfilter
    $DataDisks =  $DisksForVsan | Where-Object Model -like $BaseSiteConfig.vSAN.Common.capacitydisksfilter
    New-VsanDiskGroup -VMHost $_ -DataDiskCanonicalName $DataDisks -SsdCanonicalName $CacheDisks
}

# Update VSAN Cluster configuration
$CmdletParams = @{
    PerformanceServiceEnabled = $BaseSiteConfig.vSAN.Cluster.performanceserviceenabled
    ObjectRepairTimerMinutes = $BaseSiteConfig.vSAN.Cluster.objectrepairtimerminutes
    GuestTrimUnmap = $BaseSiteConfig.vSAN.Cluster.guesttrimunmap
    AddSilentHealthCheck = $BaseSiteConfig.vSAN.Cluster.addsilenthealthcheck
}
Get-VsanClusterConfiguration $BaseSiteConfig.Common.clustername | Set-VsanClusterConfiguration @CmdletParams
Test-VsanClusterHealth -Cluster (Get-Cluster $BaseSiteConfig.Common.clustername)

# Update SSO configuration
# $CmdletParams = @{
#     Server = $VMDeploymentConfig.VCSA.Appliance.fqdn
#     User = $VMDeploymentConfig.VCSA.Appliance.ssoaccount
#     Password = $VMDeploymentConfig.VCSA.Appliance.ssopassword
#     SkipCertificateCheck = $true
# }
# Connect-SsoAdminServer @CmdletParams

# Update Cluster configuration
$CmdletParams = @{
    Cluster = Get-Cluster $BaseSiteConfig.Common.clustername
    HAEnabled = $true
    HAAdmissionControlEnabled = $false
    DrsEnabled = $true
    Confirm = $false
}
Set-Cluster @CmdletParams

# Suppress warnings
$VMHosts | ForEach-Object {
    $VMHost = $_
    $BaseSiteConfig.ESXi.Common.VMHostAdvancedSettings.GetEnumerator() | ForEach-Object {
        Get-AdvancedSetting -Entity $VMHost -Name $_.Name | Set-AdvancedSetting -Value $_.Value -Confirm:$false
    }
}

# Subscribe to Content Libraries
$CmdletParams = @{
    Server = $VMDeploymentConfig.VCSA.Appliance.fqdn
    User = $VMDeploymentConfig.VCSA.Appliance.ssoaccount
    Password = $VMDeploymentConfig.VCSA.Appliance.ssopassword
}
Connect-CisServer @CmdletParams
$ContentLibraries | ForEach-Object {
    $CmdletParams = $_
    if ($CmdletParams.SubscriptionUrl) {
        if (-not (Get-ContentLibrary -Name $CmdletParams.LibraryName -Subscribed -ErrorAction SilentlyContinue)) {
            New-SubscribedContentLibrary @CmdletParams
        } else {
            Write-Host "$($CmdletParams.LibraryName) found. Skipping.."
        }
    } else {
        if (-not (Get-ContentLibrary -Name $CmdletParams.Name -Local -ErrorAction SilentlyContinue)) {
            New-ContentLibrary @CmdletParams
        } else {
            Write-Host "$($CmdletParams.Name) found. Skipping.."
        }
    }
}
$ContentLibraryItems | ForEach-Object {
    $CmdletParams = $_
    if (-not (Get-ContentLibraryItem -ContentLibrary $CmdletParams.ContentLibrary -Name $CmdletParams.Name -ErrorAction SilentlyContinue)) {
        New-ContentLibraryItem @CmdletParams
    } else {
        Write-Host "$($CmdletParams.ContentLibrary)/$($CmdletParams.Name) found. Skipping.."
    }
}

# Upload ISO files to vSAN Datastore
$vSANDatastorePath = Join-Path -Path vmstore: -ChildPath (Join-Path -Path $BaseSiteConfig.Common.dcname -ChildPath $BaseSiteConfig.vSAN.Cluster.datastorename)
Copy-DatastoreItem $ISODir $vSANDatastorePath -Recurse -ErrorAction SilentlyContinue

# Create Guest OS template
$PackerWorkingDir = $VMDeploymentConfig.WindowsTemplate.PackerWorkingDir
$PackerJsonFilename = Join-Path -Path $PackerWorkingDir -ChildPath $VMDeploymentConfig.WindowsTemplate.PackerJsonFilename
$PackerJsonTmpFilename = Join-Path -Path $TMPDir -ChildPath $VMDeploymentConfig.WindowsTemplate.PackerJsonTmpFilename
Set-Location $PackerWorkingDir

$DeploymentJsonObject = Get-Content $PackerJsonFilename | Out-String | ConvertFrom-Json
$DeploymentJsonObject.builders[0].vcenter_server = $VMDeploymentConfig.WindowsTemplate.builders.vcenter_server
$DeploymentJsonObject.builders[0].username = $VMDeploymentConfig.WindowsTemplate.builders.username
$DeploymentJsonObject.builders[0].password = $VMDeploymentConfig.WindowsTemplate.builders.password
$DeploymentJsonObject.builders[0].datacenter = $VMDeploymentConfig.WindowsTemplate.builders.datacenter
$DeploymentJsonObject.builders[0].cluster = $VMDeploymentConfig.WindowsTemplate.builders.cluster
$DeploymentJsonObject.builders[0].datastore = $VMDeploymentConfig.WindowsTemplate.builders.datastore
$DeploymentJsonObject.builders[0].vm_name = $VMDeploymentConfig.WindowsTemplate.builders.vm_name
$DeploymentJsonObject.builders[0].winrm_username = $VMDeploymentConfig.WindowsTemplate.builders.winrm_username
$DeploymentJsonObject.builders[0].winrm_password = $VMDeploymentConfig.WindowsTemplate.builders.winrm_password
$DeploymentJsonObject.provisioners[0].elevated_user = $VMDeploymentConfig.WindowsTemplate.provisioners.elevated_user
$DeploymentJsonObject.provisioners[0].elevated_password = $VMDeploymentConfig.WindowsTemplate.provisioners.elevated_password
$DeploymentJson = $DeploymentJsonObject | ConvertTo-Json -Depth 5
[System.Text.RegularExpressions.Regex]::Unescape($DeploymentJson) | Out-File -Encoding Ascii -FilePath $PackerJsonTmpFilename
..\packer.exe build $PackerJsonTmpFilename

# Modify and convert to VM Template
$VirtualMachineConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
$VirtualMachineConfigSpec.DeviceChange = New-Object VMware.Vim.VirtualDeviceConfigSpec[] (2)
$VirtualMachineConfigSpec.DeviceChange[0] = New-Object VMware.Vim.VirtualDeviceConfigSpec
$VirtualMachineConfigSpec.DeviceChange[0].Device = New-Object VMware.Vim.VirtualMachineVideoCard
$VirtualMachineConfigSpec.DeviceChange[0].Device.UseAutoDetect = $true
$VirtualMachineConfigSpec.DeviceChange[0].Device.Key = 500
$VirtualMachineConfigSpec.DeviceChange[0].Operation = 'edit'
$VirtualMachineConfigSpec.DeviceChange[1] = New-Object VMware.Vim.VirtualDeviceConfigSpec
$VirtualMachineConfigSpec.DeviceChange[1].Device = New-Object VMware.Vim.VirtualCdrom
$VirtualMachineConfigSpec.DeviceChange[1].Device.Key = 3001
$VirtualMachineConfigSpec.DeviceChange[1].Operation = 'remove'
$DeploymentJsonObject = Get-Content $PackerJsonFilename | Out-String | ConvertFrom-Json
$VMView = Get-View -VIObject (Get-VM -Name $DeploymentJsonObject.builders.vm_name)
$VMView.ReconfigVM_Task($VirtualMachineConfigSpec)
$VMView.MarkAsTemplate()


## Deploy DNS VMs

# Create vDS and vDPortgroups
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    # Create vDS and change uplink name
    if (-not ($VDSwitch = Get-VDSwitch $SiteConfig.VDS.Switch.Name -ErrorAction SilentlyContinue)) {
        $CmdletParams = @{
            Location = Get-Datacenter $BaseSiteConfig.Common.dcname
            Mtu = $SiteConfig.VDS.Switch.Mtu
            Name = $SiteConfig.VDS.Switch.Name
            NumUplinkPorts = $SiteConfig.VDS.Switch.NumUplinkPorts
            Confirm = $false
        }
        $VDSwitch = New-VDSwitch @CmdletParams
    }
    $DVSConfigSpec = New-Object VMware.Vim.DVSConfigSpec
    $DVSConfigSpec.ConfigVersion = $VDSwitch.ExtensionData.Config.ConfigVersion
    # Change uplink name
    $DVSUplinkPortPolicy = New-Object VMware.Vim.DVSNameArrayUplinkPortPolicy
    $DVSUplinkPortPolicy.UplinkPortName = $SiteConfig.VDS.Switch.UplinkPortName
    $DVSConfigSpec.UplinkPortPolicy = $DVSUplinkPortPolicy
    $VDSwitch.ExtensionData.ReconfigureDvs($DVSConfigSpec)

    # Create vDPortgroups
    $SiteConfig.VDS.Portgroups.GetEnumerator() | ForEach-Object {
        $PGName = $_.Value.Name
        if (-not ($VDPortGroup = Get-VDPortgroup -VDSwitch $VDSwitch -Name $PGName -ErrorAction SilentlyContinue)) {
            Write-Host -NoNewline "Creating VDPortgroup $($PGName).."
            if ($_.Value.VlanId) {
                $VDPortGroup = New-VDPortgroup -VDSwitch $VDSwitch -Name $PGName -VlanId $_.Value.VlanId
            } else {
                $VDPortGroup = New-VDPortgroup -VDSwitch $VDSwitch -Name $PGName -VlanTrunkRange "0-4094"
            }
            Write-Host -ForegroundColor Green "OK"
        }
        $CmdletParams = @{
            Confirm = $false
        }
        if ($_.Value.UplinksActive) { $CmdletParams.ActiveUplinkPort = $_.Value.UplinksActive }
        if ($_.Value.UplinksStandby) { $CmdletParams.StandbyUplinkPort = $_.Value.UplinksStandby }
        if ($_.Value.UplinksUnused) { $CmdletParams.UnusedUplinkPort = $_.Value.UplinksUnused }
        Get-VDUplinkTeamingPolicy -VDPortgroup $VDPortGroup | Set-VDUplinkTeamingPolicy @CmdletParams | Out-Null
    }
}

# Create VMs
$Tasks = @()
$BaseSiteConfig, $NestedSiteConfig | ForEach-Object {
    $_ | ForEach-Object {
        $CmdletParams = @{
            OSType = "Windows"
            NamingScheme = "Fixed"
            NamingPrefix = $_.VM.DC.hostname
            FullName = $_.VM.DC.username
            OrgName = $_.Common.domain
            TimeZone = "Korea: Seoul"
            Workgroup = "WORKGROUP"
            ChangeSid = $true
            AdminPassword = $_.VM.DC.password
        }
        $OSCustomizationSpec = New-OSCustomizationSpec @CmdletParams
        $CmdletParams = @{
            OSCustomizationNicMapping = Get-OSCustomizationNicMapping -OSCustomizationSpec $OSCustomizationSpec
            Position = 1
            IpMode = "UseStaticIP"
            IPAddress = $_.VM.DC.ipaddress
            SubnetMask = $_.Common.netmask
            DefaultGateway = $_.Common.gateway
            Dns = $_.VM.DC.dns
            Confirm = $false
        }
        $OSCustomizationNicMapping = Set-OSCustomizationNicMapping @CmdletParams
        $CmdletParams = @{
            Template = $DeploymentJsonObject.builders.vm_name
            Name = $_.VM.DC.vmname
            VMHost = $FirstHostConfig.hostname
            Datastore = $FirstHostConfig.vsandatastorename
            Portgroup = Get-VDPortgroup $_.VM.DC.portgroup
            OSCustomizationSpec = $OSCustomizationSpec
            RunAsync = $true
        }
        $Tasks += New-VM @CmdletParams
        Remove-OSCustomizationNicMapping $OSCustomizationNicMapping -Confirm:$false
        Remove-OSCustomizationSpec $OSCustomizationSpec -Confirm:$false
    }
}
$Tasks | Wait-Task

# Start newly created VMs
$BaseSiteConfig, $NestedSiteConfig | ForEach-Object {
    $_ | ForEach-Object {
        Start-VM $_.VM.DC.vmname
    }
}
$BaseSiteConfig, $NestedSiteConfig | ForEach-Object {
    $_ | ForEach-Object {
        Write-Host -NoNewLine "Starting VM $($_.VM.DC.vmname)."
        $CmdletParams = @{
            VM = $_.VM.DC.vmname
            GuestUser = $_.VM.DC.username
            GuestPassword = $_.VM.DC.password
            ScriptText = "(Get-Service VMTools).Status"
            Confirm = $false
            ErrorAction = "SilentlyContinue"
        }
        Do {
            $Result = Invoke-VMScript @CmdletParams
            Start-Sleep -Seconds 5
            Write-Host -NoNewLine "."
        } Until ($Result.ScriptOutput -like "Running*")
        Write-Host "OK"
    }
}

# Apply IP configuration again
$BaseSiteConfig, $NestedSiteConfig | ForEach-Object {
    $_ | ForEach-Object {
        $Script = @"
Remove-NetIPAddress -InterfaceAlias `"Ethernet0`" -Confirm:`$false -ErrorAction SilentlyContinue
Remove-NetRoute -InterfaceAlias `"Ethernet0`" -Confirm:`$false -ErrorAction SilentlyContinue
New-NetIPAddress -InterfaceAlias `"Ethernet0`" -IPAddress `"$($_.VM.DC.ipaddress)`" -PrefixLength 24 -DefaultGateway `"$($_.Common.gateway)`"
Set-DnsClientServerAddress -InterfaceAlias `"Ethernet0`" -ResetServerAddresses
Get-DnsClientServerAddress -InterfaceAlias `"Ethernet0`" -AddressFamily IPv4 | Set-DnsClientServerAddress -ServerAddresses @("$($_.VM.DC.dns)")
Get-DnsClientServerAddress -InterfaceAlias `"Ethernet0`" -AddressFamily IPv6 | Set-DnsClientServerAddress -ServerAddresses @("::1")
"@
        $CmdletParams = @{
            VM = $_.VM.DC.vmname
            GuestUser = $_.VM.DC.username
            GuestPassword = $_.VM.DC.password
            ScriptText = $Script
            Confirm = $false
            ErrorAction = "SilentlyContinue"
        }
        Invoke-VMScript @CmdletParams
    }
}
 
# Install AD Domain Service
$BaseSiteConfig | ForEach-Object {
    $Script = @"
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
`$CmdletParams = `@{
    DomainName = `"$($_.Common.domain)`"
    DomainNetBiosName = `"$($_.Common.domainnetbiosname)`"
    InstallDns = `$true
    NoRebootOnCompletion = `$false
    SafeModeAdministratorPassword = `(ConvertTo-SecureString $($_.VM.DC.password) -AsPlainText -Force)
    Confirm = `$false
}
Install-ADDSForest `@CmdletParams
"@
    $CmdletParams = @{
        VM = $_.VM.DC.vmname
        GuestUser = $_.VM.DC.username
        GuestPassword = $_.VM.DC.password
        ScriptText = $Script
        Confirm = $false
        ErrorAction = "SilentlyContinue"
    }
    Write-Host -NoNewLine "Installing AD Domain Service to `"$($CmdletParams.VM)`"."
    Invoke-VMScript @CmdletParams

    $CmdletParams.ScriptText = "(Get-Service BITS).Status"
    Do {
        $Result = Invoke-VMScript @CmdletParams
        Start-Sleep -Seconds 10
        Write-Host -NoNewLine "."
    } Until ($Result.ScriptOutput -like "Stopped*")
    Write-Host "OK"
}
$NestedSiteConfig | ForEach-Object {
    $Script = @"
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools
`$UserName = `"$($_.VM.DC.username)`" + "@" + `"$($_.Common.parentdomain)`"
`$Password = ConvertTo-SecureString `"$($_.VM.DC.password)`" -AsPlainText -Force
`$Credential = New-Object System.Management.Automation.PSCredential(`$UserName, `$Password)
`$CmdletParams = `@{
    ParentDomainName = `"$($_.Common.parentdomain)`"
    NewDomainName = `"$(($_.Common.domain -split "\.")[0])`"
    NewDomainNetBiosName = `"$($_.Common.domainnetbiosname)`"
    Credential = `$Credential
    DomainType = `"$($_.Common.domaintype)`"
    InstallDns = `$true
    NoRebootOnCompletion = `$false
    SafeModeAdministratorPassword = `$Password
    Confirm = `$false
}
Install-ADDSDomain `@CmdletParams
"@
    $CmdletParams = @{
        VM = $_.VM.DC.vmname
        GuestUser = $_.VM.DC.username
        GuestPassword = $_.VM.DC.password
        ScriptText = $Script
        Confirm = $false
        ErrorAction = "SilentlyContinue"
    }
    Write-Host -NoNewLine "Installing AD Domain Service to `"$($CmdletParams.VM)`"."
    Invoke-VMScript @CmdletParams

    $CmdletParams.ScriptText = "(Get-Service BITS).Status"
    Do {
        $Result = Invoke-VMScript @CmdletParams
        Start-Sleep -Seconds 10
        Write-Host -NoNewLine "."
    } Until ($Result.ScriptOutput -like "Stopped*")
    Write-Host "OK"
}

# Add Reverse Lookup Zone
$BaseSiteConfig, $NestedSiteConfig | ForEach-Object {
    $_ | ForEach-Object {
        $DNSVMipaddress = ([IpAddress]$_.VM.DC.ipaddress).Address
        $DNSVMnetmask = ([IpAddress]$_.Common.netmask).Address
        $DNSVMnetworkaddress = ([IpAddress]($DNSVMipaddress -band $DNSVMnetmask)).IpAddressToString
        $DNSVMcidr = ([System.Convert]::ToString(([IpAddress]$_.Common.netmask).Address, 2)).Length
        $NetworkId = $($DNSVMnetworkaddress + "/" + $DNSVMcidr)

        $CmdletParams = @{
            VM = $_.VM.DC.vmname
            GuestUser = $_.VM.DC.username
            GuestPassword = $_.VM.DC.password
            ScriptText = "Add-DnsServerPrimaryZone -NetworkId `"$NetworkId`" -ReplicationScope `"Forest`""
            Confirm = $false
            ErrorAction = "SilentlyContinue"
        }
        Invoke-VMScript @CmdletParams

        if ($_.VM.DC.additionalzones) {
            $_.VM.DC.additionalzones | ForEach-Object {
                $CmdletParams.ScriptText = "Add-DnsServerPrimaryZone -NetworkId `"$_`" -ReplicationScope `"Forest`""
                $CmdletParams
                Invoke-VMScript @CmdletParams
            }
        }
    }
}

# Add DNS Records
$BaseSiteConfig, $NestedSiteConfig | ForEach-Object {
    $_ | ForEach-Object {
        $ZoneName = $_.Common.domain
        $VM = $_.VM.DC.vmname
        $GuestUser = $_.VM.DC.username
        $GuestPassword = $_.VM.DC.password

        $_.VM.DC.dnsrecords | ForEach-Object {
            $Script = @"
`$CmdletParams = `@{
    ZoneName = `"$ZoneName`"
    Name = `"$($_.hostname)`"
    IPv4Address = `"$($_.ipaddress)`"
    CreatePtr = `$true
}
Add-DnsServerResourceRecordA `@CmdletParams
"@
            $CmdletParams = @{
                VM = $VM
                GuestUser = $GuestUser
                GuestPassword = $GuestPassword
                ScriptText = $Script
                Confirm = $false
                ErrorAction = "SilentlyContinue"
            }
            Invoke-VMScript @CmdletParams
        }
    }
}


## Enable vSAN File Service
Add-VsanFileServiceOvf
$FileServiceNetwork = Get-VirtualNetwork $BaseSiteConfig.VDS.Portgroups.vSANFS.Name
$Configuration = Get-VsanClusterConfiguration -Cluster $BaseSiteConfig.Common.clustername
$Configuration = Set-VsanClusterConfiguration -Configuration $Configuration -FileServiceEnabled:$true -FileServiceNetwork $FileServiceNetwork

# Create vSAN File Service Domain
$VsanFileServerIpConfig = @()
$BaseSiteConfig.VM.DC.dnsrecords | Where-Object category -eq "vsanfs" | ForEach-Object {
    $CmdletParams = @{
        IpAddress = $_.ipaddress
        SubnetMask = $BaseSiteConfig.vSAN.FileService.netmask
        Gateway = $BaseSiteConfig.vSAN.FileService.gateway
        Fqdn = $($_.hostname + "." + $BaseSiteConfig.Common.domain)
        IsPrimary = $false
    }
    if ($_.hostname -eq $BaseSiteConfig.vSAN.FileService.primarynode) {
        $CmdletParams.IsPrimary = $true
    }
    $VsanFileServerIpConfig += New-VsanFileServerIpConfig @CmdletParams
}
$CmdletParams = @{
    Name = $BaseSiteConfig.vSAN.FileService.fsdomain
    Cluster = $BaseSiteConfig.Common.clustername
    VsanFileServerIpConfig = $VsanFileServerIpConfig
    DnsServerAddress = $BaseSiteConfig.Common.dns
    DnsSuffix = $BaseSiteConfig.Common.domain
}
$FileServiceDomain = New-VsanFileServiceDomain @CmdletParams

# Create vSAN File Share
$CmdletParams = @{
    IPSetOrSubnet = "*"
    AllowSquashRoot = $true
    VsanFileShareAccessPermission = "ReadWrite"
}
$FileShareNetworkPermission = New-VsanFileShareNetworkPermission @CmdletParams
$BaseSiteConfig.vSAN.FileService.fileshare | ForEach-Object {
    $CmdletParams = @{
        FileServiceDomain = $FileServiceDomain
        Name = $_
        FileShareNetworkPermission = $FileShareNetworkPermission
    }
    New-VsanFileShare @CmdletParams
}


## Deploy nested ESXi VMs

# Deploy from Nested ESXi Template
$Cluster = Get-Cluster $BaseSiteConfig.Common.clustername
$ContentLibraryItem = (Get-ContentLibraryItem -Name $VMDeploymentConfig.ESXiTemplate.OVFName)
$OvfConfiguration = Get-OvfConfiguration -ContentLibraryItem $ContentLibraryItem -Target $Cluster
$OvfConfiguration.EULAs.Accept.Value = $true
$NetworkMapLabel = ($OvfConfiguration.ToHashTable().keys | Where-Object {$_ -Match "NetworkMapping"}).replace("NetworkMapping.","").replace("-","_").replace(" ","_")
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    if (-not ($ResourcePool = Get-ResourcePool -Name $SiteConfig.Common.resourcepoolname -ErrorAction SilentlyContinue)) {
        $ResourcePool = New-ResourcePool -Name $SiteConfig.Common.resourcepoolname -Location $Cluster
    }
    $Tasks = @()
    $OvfConfiguration.NetworkMapping.$NetworkMapLabel.Value = "Nested-1Gb"
    $SiteConfig.ESXi.Host | ForEach-Object {
        $OvfConfiguration.Common.guestinfo.vlan.Value =  $SiteConfig.ESXi.Common.management_vlan
        $OvfConfiguration.Common.guestinfo.hostname.Value =  $_.hostname
        $OvfConfiguration.Common.guestinfo.ipaddress.Value = $_.ipaddress
        $OvfConfiguration.Common.guestinfo.netmask.Value = $SiteConfig.Common.netmask
        $OvfConfiguration.Common.guestinfo.gateway.Value = $SiteConfig.Common.gateway
        $OvfConfiguration.Common.guestinfo.dns.Value = $SiteConfig.Common.dns
        $OvfConfiguration.Common.guestinfo.domain.Value = $SiteConfig.Common.domain
        $OvfConfiguration.Common.guestinfo.ntp.Value = $SiteConfig.Common.ntp
        $OvfConfiguration.Common.guestinfo.syslog.Value = $null
        $OvfConfiguration.Common.guestinfo.password.Value =  $SiteConfig.ESXi.Common.password
        $OvfConfiguration.Common.guestinfo.ssh.Value = $true 
        $CmdletParams = @{
            VMHost = Get-VMHost $BaseSiteConfig.ESXi.Host[(Get-Random -Minimum 1 -Maximum $BaseSiteConfig.ESXi.Count)].hostname
            ContentLibraryItem = $ContentLibraryItem
            Datastore = $BaseSiteConfig.vSAN.Cluster.datastorename
            DiskStorageFormat = "thin"
            Name = $($_.hostname + "." + $SiteConfig.Common.domain)
            OvfConfiguration = $OvfConfiguration
            ResourcePool = $ResourcePool
            RunAsync = $true
            WhatIf = $false
        }
        if (-not (Get-VM $CmdletParams.Name -ErrorAction SilentlyContinue)) {
            $Tasks += New-VM @CmdletParams
        }
    }
    $Tasks | Wait-Task

    $Tasks | ForEach-Object {
        Set-VM -VM $_.Result -NumCpu $SiteConfig.ESXi.Common.numcpu -MemoryGB $SiteConfig.ESXi.Common.memorygb -Confirm:$false
        $CmdletParams = @{
            VM = $_.Result
            Type = "Vmxnet3"
            Portgroup = Get-VDPortgroup -Name "Nested-10Gb"
            StartConnected = $true
            Confirm = $false
        }
        New-NetworkAdapter @CmdletParams
        New-NetworkAdapter @CmdletParams
    }
}

# Create VM Folders and move the VMs into
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $DCView = (Get-View -VIObject (Get-Datacenter -Name $BaseSiteConfig.Common.dcname))
    $VMFolderView = Get-View $DCView.VMFolder
    $VMFolderName = $SiteConfig.Common.siteprefix + " " + "VMs"
    if (-not (Get-Folder -Type VM -Name $VMFolderName -ErrorAction SilentlyContinue)) {
        $VMFolderView.CreateFolder($VMFolderName) | Out-Null
    }
    $VMFolder = Get-Folder -Type VM -Name $VMFolderName
    $SiteConfig.ESXi.Host | ForEach-Object {
        $VM = Get-VM -Name $($_.hostname + "." + $SiteConfig.Common.domain)
        Move-VM -VM $VM -InventoryLocation $VMFolder | Out-Null
    }
}

# Power On Nested ESXi VMs
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.ESXi.Host | ForEach-Object {
        Start-VM -VM $($_.hostname + "." + $SiteConfig.Common.domain) -RunAsync -Confirm:$false
    }
}
Write-Host -NoNewline "Waiting for Nested ESXi Hosts start up."
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.ESXi.Host | ForEach-Object {
        $CmdletParams = @{
            Server = $($_.hostname + "." + $SiteConfig.Common.domain)
            User = $SiteConfig.ESXi.Common.username
            Password = $SiteConfig.ESXi.Common.password
            ErrorAction = "SilentlyContinue"
        }
        Do {
            $tmpconn = Connect-VIServer @CmdletParams
            Start-Sleep -Seconds 2
            Write-Host -NoNewline "."
        } Until ($tmpconn)
        Disconnect-VIServer $tmpconn -Confirm:$false
    }
}
Write-Host -ForegroundColor Green "OK"

# Create cluster corresponding to each nested site's name and add VMHosts to cluster
$Tasks = @()
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    if (-not (Get-Cluster -Name $SiteConfig.Common.clustername -ErrorAction SilentlyContinue)) {
        $CmdletParams = @{
            Name = $SiteConfig.Common.clustername
            Location = Get-Datacenter -Name ($BaseSiteConfig.Common.dcname)
            HAEnabled = $false
            #HAAdmissionControlEnabled = $false
            DrsEnabled = $true
            Confirm = $false
        }
        New-Cluster @CmdletParams
    }
    $SiteConfig.ESXi.Host | ForEach-Object {
        $CmdletParams = @{
            Name = $($_.hostname + "." + $SiteConfig.Common.domain)
            Location = Get-Cluster -Name $SiteConfig.Common.clustername
            User = $SiteConfig.ESXi.Common.username
            Password = $SiteConfig.ESXi.Common.password
            Force = $true
            RunAsync = $true
        }
        $Tasks += Add-VMHost @CmdletParams
    }
}
$Tasks | Wait-Task

# Nested ESXi optimization
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.ESXi.Host | ForEach-Object {
        $VMHost = Get-VMHost $($_.hostname + "." + $SiteConfig.Common.domain)
        # Net.FollowHardwareMac should be disabled
        Get-AdvancedSetting -Entity $VMHost -Name Net.FollowHardwareMac | Set-AdvancedSetting -Value 0 -Confirm:$false
        $VM = Get-VM -Name $($_.hostname + "." + $SiteConfig.Common.domain)
        Stop-VMGuest -VM $VM -Confirm:$false
    }
}

# Waitfor VM shutdown..........................


$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.ESXi.Host | ForEach-Object {
        $VM = Get-VM -Name $($_.hostname + "." + $SiteConfig.Common.domain)
        # Change MAC address of the first network adapter
        $vNIC = Get-NetworkAdapter -VM $VM -Name "Network adapter 1"
        $CurrentMAC = $vNIC.MacAddress -split ":"
        if ([int]("0x" + $CurrentMAC[4]) -lt 255) {
            $CurrentMAC[4] = "{0:x2}" -f ([int]("0x" + $CurrentMAC[4]) + 1)
        } else {
            $CurrentMAC[4] = "{0:x2}" -f ([int]("0x" + $CurrentMAC[4]) - 1)
        }
        $NewMAC = $CurrentMAC -join ":"
        Set-NetworkAdapter -NetworkAdapter $vNIC -MacAddress $NewMAC -Confirm:$false
    }
}

# Power On Nested ESXi Hosts again
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.ESXi.Host | ForEach-Object {
        Start-VM -VM $($_.hostname + "." + $SiteConfig.Common.domain) -RunAsync -Confirm:$false
    }
}
Write-Host -NoNewline "Waiting for Nested ESXi Hosts start up."
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.ESXi.Host | ForEach-Object {
        $CmdletParams = @{
            Server = $($_.hostname + "." + $SiteConfig.Common.domain)
            User = $SiteConfig.ESXi.Common.username
            Password = $SiteConfig.ESXi.Common.password
            ErrorAction = "SilentlyContinue"
        }
        Do {
            $tmpconn = Connect-VIServer @CmdletParams
            Start-Sleep -Seconds 2
            Write-Host -NoNewline "."
        } Until ($tmpconn)
        Disconnect-VIServer $tmpconn -Confirm:$false
    }
}
Write-Host -ForegroundColor Green "OK"

# Set Management portgroup uplink redundant
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.ESXi.Host | ForEach-Object {
        $VMHost = Get-VMHost -Name $($_.hostname + "." + $SiteConfig.Common.domain)

        $PhysicalNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -Physical -Name "vmnic1"
        $VirtualSwitch = Get-VirtualSwitch -VMHost $VMHost -Name "vSwitch0"
        Add-VirtualSwitchPhysicalNetworkAdapter -VirtualSwitch $VirtualSwitch -VMHostPhysicalNic $PhysicalNIC -Confirm:$false
        $VirtualPortGroup = Get-VirtualPortGroup -VMHost $VMHost -Name "Management Network"
        $Policy = Get-NicTeamingPolicy -VirtualPortGroup $VirtualPortGroup
        Set-NicTeamingPolicy -VirtualPortGroupPolicy $Policy -InheritFailoverOrder:$true -Confirm:$false
    }
}

# Add VMHosts to VDSwitch and migrate vNICs into VDSwitch
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $VDSwitch = Get-VDSwitch -Name $SiteConfig.VDS.Switch.Name
    $SiteConfig.ESXi.Host | ForEach-Object {
        $VMHost = Get-VMHost -Name $($_.hostname + "." + $SiteConfig.Common.domain)
        Add-VDSwitchVMHost -VDSwitch $VDSwitch -VMHost $VMHost
        $PhysicalNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -Physical -Name "vmnic0"
        $VirtualNIC = Get-VMHostNetworkAdapter -VMHost $VMHost -Name "vmk0"
        Remove-VirtualSwitchPhysicalNetworkAdapter -VMHostNetworkAdapter $PhysicalNIC -Confirm:$false
        $CmdletParams = @{
            DistributedSwitch = $VDSwitch
            VMHostPhysicalNic = $PhysicalNIC
            VMHostVirtualNic = $VirtualNic
            VirtualNicPortgroup = $SiteConfig.VDS.Portgroups.Management.Name
            Confirm = $false
        }
        Add-VDSwitchPhysicalNetworkAdapter @CmdletParams
        Get-VMHostNetworkAdapter -VMHost $VMHost -Physical -Name $SiteConfig.VDS.Switch.UplinkPortName | ForEach-Object {
            Add-VDSwitchPhysicalNetworkAdapter -DistributedSwitch $VDSwitch -VMHostPhysicalNic $_ -Confirm:$false -ErrorAction SilentlyContinue
        }
        Get-VirtualSwitch -VMHost $VMHost -Standard | Remove-VirtualSwitch -Confirm:$false
    }
}

# Create vmk ports for vMotion and vSAN File Service
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $VDSwitch = Get-VDSwitch -Name $SiteConfig.VDS.Switch.Name
    $SiteConfig.ESXi.Host | ForEach-Object {
        $VMHost = Get-VMHost -Name $($_.hostname + "." + $SiteConfig.Common.domain)
        $VMHostNetworkStack = Get-VMHostNetworkStack -VMHost $VMHost | Where-Object Id -eq vmotion
        $CmdletParams = @{
            VMHost = $VMHost
            Mtu = 9000
            VirtualSwitch = $VDSwitch
            PortGroup = $SiteConfig.VDS.Portgroups.vMotion.Name
            NetworkStack = $VMHostNetworkStack
        }
        New-VMHostNetworkAdapter @CmdletParams | Out-Null
        $CmdletParams = @{
            VMHost = $VMHost
            Mtu = 9000
            VirtualSwitch = $VDSwitch
            PortGroup = $SiteConfig.VDS.Portgroups.vSANFS.Name
            VsanTrafficEnabled = $true
        }
        New-VMHostNetworkAdapter @CmdletParams | Out-Null
    }
}

# Mount vSAN File Service Datastore
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.ESXi.Host | ForEach-Object {
        $VMHost = Get-VMHost -Name $($_.hostname + "." + $SiteConfig.Common.domain)
        if (-not (Get-Datastore -VMHost $VMHost -Name $SiteConfig.Common.datastorename -ErrorAction SilentlyContinue)) {
            $CmdletParams = @{
                VMHost = $VMHost
                Nfs = $true
                Name = $SiteConfig.Common.datastorename
                NfsHost = (Get-VsanFileShare -Name $SiteConfig.Common.datastorename).IPAddress
                PATH = "/" + $SiteConfig.Common.datastorename
                Confirm = $false
                Whatif = $false
            }
            $CmdletParams
            New-Datastore @CmdletParams
        }
    }
}

# Enable vSphere HA
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $spec.DasConfig = New-Object VMware.Vim.ClusterDasConfigInfo
    $spec.DasConfig.Enabled = $true
    $spec.DasConfig.Option = New-Object VMware.Vim.OptionValue[] (1)
    $spec.DasConfig.Option[0] = New-Object VMware.Vim.OptionValue
    $spec.DasConfig.Option[0].Value = 'true'
    $spec.DasConfig.Option[0].Key = 'das.ignoreInsufficientHbDatastore'
    $modify = $true
    $_this = Get-Cluster $SiteConfig.Common.clustername | Get-View

    $task = $_this.ReconfigureComputeResource_Task($spec, $modify)
    $task1 = Get-Task -Id ("Task-$($task.value)")
    $task1 | Wait-Task
}

# Suppress warnings
$NestedSiteConfig | ForEach-Object {
    $SiteConfig = $_
    $SiteConfig.ESXi.Host | ForEach-Object {
        $VMHost = Get-VMHost -Name $($_.hostname + "." + $SiteConfig.Common.domain)
        $SiteConfig.ESXi.Common.VMHostAdvancedSettings.GetEnumerator() | ForEach-Object {
            Get-AdvancedSetting -Entity $VMHost -Name $_.Name | Set-AdvancedSetting -Value $_.Value -Confirm:$false
        }
    }
}


## Deploy Tanzu (Using vSphere Networking)

# Deploy HAProxy from OVA Template
$OvfConfiguration = Get-OvfConfiguration -Ovf $VMDeploymentConfig.HAProxy.OVAFilename
$OvfConfiguration.appliance.permit_root_login.Value = $VMDeploymentConfig.HAProxy.appliance_permit_root_login
$OvfConfiguration.appliance.root_pwd.Value = $VMDeploymentConfig.HAProxy.appliance_root_pwd
$OvfConfiguration.DeploymentOption.Value = $VMDeploymentConfig.HAProxy.DeploymentOption
$OvfConfiguration.NetworkMapping.Management.Value = $VMDeploymentConfig.HAProxy.NetworkMapping_Management
$OvfConfiguration.NetworkMapping.Workload.Value = $VMDeploymentConfig.HAProxy.NetworkMapping_Workload
$OvfConfiguration.NetworkMapping.Frontend.Value = $VMDeploymentConfig.HAProxy.NetworkMapping_Frontend
$OvfConfiguration.loadbalance.haproxy_user.Value = $VMDeploymentConfig.HAProxy.loadbalance_haproxy_user
$OvfConfiguration.loadbalance.haproxy_pwd.Value = $VMDeploymentConfig.HAProxy.loadbalance_haproxy_pwd
$OvfConfiguration.loadbalance.service_ip_range.Value = $VMDeploymentConfig.HAProxy.loadbalance_service_ip_range
$OvfConfiguration.network.hostname.Value = $VMDeploymentConfig.HAProxy.network_hostname
$OvfConfiguration.network.nameservers.Value = $VMDeploymentConfig.HAProxy.network_nameservers
$OvfConfiguration.network.management_ip.Value = $VMDeploymentConfig.HAProxy.network_management_ip
$OvfConfiguration.network.management_gateway.Value = $VMDeploymentConfig.HAProxy.network_management_gateway
$OvfConfiguration.network.workload_ip.Value = $VMDeploymentConfig.HAProxy.network_workload_ip
$OvfConfiguration.network.workload_gateway.Value = $VMDeploymentConfig.HAProxy.network_workload_gateway

$CmdletParams = @{
    Source = $VMDeploymentConfig.HAProxy.OVAFilename
    OvfConfiguration = $OvfConfiguration
    Name = $VMDeploymentConfig.HAProxy.vm_Name
#    InventoryLocation = $VMDeploymentConfig.HAProxy.vm_InventoryLocation
    Location = $VMDeploymentConfig.HAProxy.vm_Location
    VMHost = $VMDeploymentConfig.HAProxy.vm_VMHost
    Datastore = $VMDeploymentConfig.HAProxy.vm_Datastore
    DiskStorageFormat = $VMDeploymentConfig.HAProxy.vm_DiskStorageFormat
}
$HAProxyVM = Import-VApp @CmdletParams

$ExtraOVFConfig = @{
    "frontend_ip" = $VMDeploymentConfig.HAProxy.network_frontend_ip
    "frontend_gateway" = $VMDeploymentConfig.HAProxy.network_frontend_gateway
}

# Retrieve existing OVF properties from VM
$VAppConfigProperty = $HAProxyVM.ExtensionData.Config.VAppConfig.Property

# Create a new Update spec based on the # of OVF properties to update
$VAppPropertySpecArray = New-Object VMware.Vim.VAppPropertySpec[]($ExtraOVFConfig.count)

# Find OVF property Id and update the Update Spec
foreach ($PropertyItem in $VAppConfigProperty) {
    if($ExtraOVFConfig.ContainsKey($PropertyItem.Id)) {
        $VAppPropertySpec = New-Object VMware.Vim.VAppPropertySpec
        $VAppPropertySpec.Operation = "edit"
        $VAppPropertySpec.Info = New-Object VMware.Vim.VAppPropertyInfo
        $VAppPropertySpec.Info.Key = $PropertyItem.Key
        $VAppPropertySpec.Info.value = $ExtraOVFConfig[$PropertyItem.Id]
        $VAppPropertySpecArray += $VAppPropertySpec
    }
}

$VirtualMachineConfigSpec = New-Object VMware.Vim.VirtualMachineConfigSpec
$VirtualMachineConfigSpec.vAppConfig = New-Object VMware.Vim.VmConfigSpec
$VirtualMachineConfigSpec.VAppConfig.Property = $VAppPropertySpecArray

$task = $HAProxyVM.ExtensionData.ReconfigVM_Task($VirtualMachineConfigSpec)
$task1 = Get-Task -Id ("Task-$($task.value)")
$task1 | Wait-Task

# Wait for HAProxy VM power on and finish initialization

# Wait for Contents Library synchronization
Get-Task | Where-Object Name -eq "Sync Library" | Where-Object State -eq Running | Wait-Task

# Get HAProxy CA Certificate
$CACertFile = "ca.crt"
$SourceFile = "/etc/haproxy/" + $CACertFile
$CmdletParams = @{
    VM = Get-VM "haproxy01.rainpole.lab"
    GuestToLocal = $true
    Source = $SourceFile
    Destination = ".\"
    GuestUser = "root"
    GuestPassword = $Env:SHORT_DEPLOYMENT_PASSWORD
}
Copy-VMGuestFile @CmdletParams
$CACert = (Get-Content $CACertFile -Encoding Ascii | Out-String)
Remove-Item $CACertFile

# Storage Configuration
if (-not ($TagCategory = Get-TagCategory -Name "VSANCategory" -ErrorAction SilentlyContinue)) {
    $TagCategory = New-TagCategory -Name "VSANCategory"
}
if (-not ($Tag = Get-Tag -Name "VSANTag" -Category $TagCategory -ErrorAction SilentlyContinue)) {
    $Tag = New-Tag -Name "VSANTag" -Category $TagCategory
}
$WMDatastore = Get-Datastore -Name $BaseSiteConfig.vSAN.Cluster.datastorename
if (-not (Get-TagAssignment -Entity $WMDatastore -Category $TagCategory -ErrorAction SilentlyContinue)) {
    New-TagAssignment -Tag $Tag -Entity $WMDatastore
}
if (-not ($SpbmStoragePolicy = Get-SpbmStoragePolicy -Name "VSANPolicy" -ErrorAction SilentlyContinue)) {
    $SpbmRule = New-SpbmRule -AnyOfTags $tag
    $SpbmRuleSet = New-SpbmRuleSet -Name "wcp-ruleset" -AllOfRules $SpbmRule
    $SpbmStoragePolicy = New-SpbmStoragePolicy -Name "VSANPolicy" -AnyOfRuleSets $SpbmRuleSet
}

# Enable Workload Management Cluster
if (-not ($WMCluster = Get-WMCluster $BaseSiteConfig.Common.clustername -ErrorAction SilentlyContinue)) {
    $CmdletParams = @{
        Cluster = $BaseSiteConfig.Common.clustername
        SizeHint = "Tiny"
        ManagementVirtualNetwork = Get-VirtualNetwork "Lab-Management"
        ManagementNetworkMode = "StaticRange"
        ManagementNetworkStartIPAddress = "192.168.10.31"
        ManagementNetworkGateway = "192.168.10.1"
        ManagementNetworkSubnetMask = "255.255.255.0"
        MasterDnsServerIPAddress = @("192.168.10.9")
        MasterDnsSearchDomain = "rainpole.lab"
        MasterNtpServer = @("0.kr.pool.ntp.org", "1.kr.pool.ntp.org")
        # WorkerDnsServer = @("192.168.10.9")
        ServiceCIDR = "10.96.0.0/16"
        EphemeralStoragePolicy = $SpbmStoragePolicy
        ImageStoragePolicy = $SpbmStoragePolicy
        MasterStoragePolicy = $SpbmStoragePolicy
        ContentLibrary = "tkg-cl"
        HAProxyName = "haproxy01"
        HAProxyAddressRanges = "192.168.12.128-192.168.12.254"
        HAProxyUsername = "admin"
        HAProxyPassword = $Env:SHORT_DEPLOYMENT_PASSWORD
        # HAProxyDataPlaneAddresses = "haproxy01.rainpole.lab:5556"
        HAProxyDataPlaneAddresses = "192.168.10.21:5556"
        HAProxyServerCertificateChain = $CACert
        PrimaryWorkloadNetworkSpecification = (New-WMNamespaceNetworkSpec `
            -Name "workload-1" `
            -Gateway "192.168.11.1" `
            -Subnet "255.255.255.0" `
            -AddressRanges "192.168.11.3-192.168.11.254" `
            -DistributedPortGroup "Lab-Workload" `
        )
    }
    $WMCluster = Enable-WMCluster @CmdletParams
}

# Connect SSoAdminServer and create DevOps User
$CmdletParams = @{
    Server = $VMDeploymentConfig.VCSA.Appliance.fqdn
    User = $VMDeploymentConfig.VCSA.Appliance.ssoaccount
    Password = $VMDeploymentConfig.VCSA.Appliance.ssopassword
    SkipCertificateCheck = $true
}
$SsoConn = Connect-SsoAdminServer @CmdletParams
Get-SsoPasswordPolicy | Set-SsoPasswordPolicy -PasswordLifetimeDays 999999999 | Out-Null

if (-not ($DevOpsUser = Get-SsoPersonUser -Name "DevOps" -Domain $VMDeploymentConfig.VCSA.Appliance.ssodomain)) {
    $CmdletParams = @{
        Server = $SsoConn
        UserName = "DevOps"
        Password = $Env:SHORT_DEPLOYMENT_PASSWORD
        FirstName = "DevOps"
        LastName = "User"
    }
    $DevOpsUser = New-SsoPersonUser @CmdletParams
}

# Create namespace, Assign storage policy, Grant permission to DevOps user
if (-not ($WMNamespace = Get-WMNamespace -Name "namespace-01" -ErrorAction SilentlyContinue)) {
    $WMNamespace = New-WMNamespace -Name "namespace-01" -Cluster $WMCluster.Cluster
}
if ((Get-WMNamespaceStoragePolicy -Namespace $WMNamespace).StoragePolicy -ne $SpbmStoragePolicy) {
    New-WMNamespaceStoragePolicy -Namespace $WMNamespace -StoragePolicy $SpbmStoragePolicy
}
if (-not ($WMNamespacePermission = Get-WMNamespacePermission -Namespace $WMNamespace -Domain $VMDeploymentConfig.VCSA.Appliance.ssodomain -PrincipalName $DevOpsUser.Name)) {
    $WMNamespacePermission = New-WMNamespacePermission -Namespace $WMNamespace -Role Edit -Domain $VMDeploymentConfig.VCSA.Appliance.ssodomain -PrincipalType User -PrincipalName $DevOpsUser.Name
}
# Associate VM Classes and confirm if ConfigStatus of the Namespace is "Running"

$Env:KUBECTL_VSPHERE_PASSWORD = $Env:SHORT_DEPLOYMENT_PASSWORD
kubectl vsphere login --server $WMCluster.KubernetesHostname --vsphere-username $DevOpsUser.ToString() --insecure-skip-tls-verify
kubectl apply -f tkc.yaml
kubectl vsphere login --server $WMCluster.KubernetesHostname --vsphere-username Administrator@vsphere.lab --insecure-skip-tls-verify --tanzu-kubernetes-cluster-namespace=namespace-01 --tanzu-kubernetes-cluster-name=tkgs-cluster-1
kubectl vsphere login --server $WMCluster.KubernetesHostname --vsphere-username $DevOpsUser.ToString() --insecure-skip-tls-verify --tanzu-kubernetes-cluster-namespace=namespace-01 --tanzu-kubernetes-cluster-name=tkgs-cluster-1
kubectl create clusterrolebinding default-tkg-admin-privileged-binding --clusterrole=psp:vmwaresystem-privileged --group=system:authenticated

kubectl config use-context namespace-01
[System.Text.Encoding]::UTF8.GetString(
    [System.Convert]::FromBase64String(
        (kubectl get secrets tkgs-cluster-1-ssh-password -o jsonpath='{.data.ssh-passwordkey}')
    )
)
kubectl config use-context tkgs-cluster-1







## Deploy Tanzu (Using NSX-T Data Center)

# Deploy NSX Manager from OVA Template (1st Node)
$OvfConfiguration = Get-OvfConfiguration -Ovf $VMDeploymentConfig.NSXManager.OVAFilename
$OvfConfiguration.DeploymentOption.Value = $VMDeploymentConfig.NSXManager.DeploymentOption
$OvfConfiguration.IpAssignment.IpProtocol.Value = $VMDeploymentConfig.NSXManager.IpProtocol
$OvfConfiguration.NetworkMapping.Network_1.Value = $VMDeploymentConfig.NSXManager.Network_1
$OvfConfiguration.Common.nsx_passwd_0.Value = $VMDeploymentConfig.NSXManager.nsx_passwd_0
$OvfConfiguration.Common.nsx_cli_passwd_0.Value = $VMDeploymentConfig.NSXManager.nsx_cli_passwd_0
$OvfConfiguration.Common.nsx_cli_audit_passwd_0.Value = $VMDeploymentConfig.NSXManager.nsx_cli_audit_passwd_0
$OvfConfiguration.Common.nsx_cli_username.Value = $VMDeploymentConfig.NSXManager.nsx_cli_username
$OvfConfiguration.Common.nsx_cli_audit_username.Value = $VMDeploymentConfig.NSXManager.nsx_cli_audit_username
$OvfConfiguration.Common.extraPara.Value = $VMDeploymentConfig.NSXManager.extraPara
$OvfConfiguration.Common.nsx_hostname.Value = $VMDeploymentConfig.NSXManager.nsx_hostname
$OvfConfiguration.Common.nsx_role.Value = $VMDeploymentConfig.NSXManager.nsx_role
$OvfConfiguration.Common.nsx_ip_0.Value = $VMDeploymentConfig.NSXManager.nsx_ip_0
$OvfConfiguration.Common.nsx_netmask_0.Value = $VMDeploymentConfig.NSXManager.nsx_netmask_0
$OvfConfiguration.Common.nsx_gateway_0.Value = $VMDeploymentConfig.NSXManager.nsx_gateway_0
$OvfConfiguration.Common.nsx_dns1_0.Value = $VMDeploymentConfig.NSXManager.nsx_dns1_0
$OvfConfiguration.Common.nsx_domain_0.Value = $VMDeploymentConfig.NSXManager.nsx_domain_0
$OvfConfiguration.Common.nsx_ntp_0.Value = $VMDeploymentConfig.NSXManager.nsx_ntp_0
$OvfConfiguration.Common.nsx_isSSHEnabled.Value = $VMDeploymentConfig.NSXManager.nsx_isSSHEnabled
$OvfConfiguration.Common.nsx_allowSSHRootLogin.Value = $VMDeploymentConfig.NSXManager.nsx_allowSSHRootLogin
$OvfConfiguration.Common.nsx_swIntegrityCheck.Value = $VMDeploymentConfig.NSXManager.nsx_swIntegrityCheck

$CmdletParams = @{
    Source = $VMDeploymentConfig.NSXManager.OVAFilename
    OvfConfiguration = $OvfConfiguration
    Name = "nsxmgr01"
#    InventoryLocation = $VMDeploymentConfig.HAProxy.vm_InventoryLocation
    Location = $VMDeploymentConfig.NSXManager.vm_Location
    VMHost = $VMDeploymentConfig.NSXManager.vm_VMHost
    Datastore = $VMDeploymentConfig.NSXManager.vm_Datastore
    DiskStorageFormat = $VMDeploymentConfig.NSXManager.vm_DiskStorageFormat
}
$NSXManagerVM = Import-VApp @CmdletParams
$NSXManagerVM | Start-VM -RunAsync

$auth = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes(
    $VMDeploymentConfig.NSXManager.nsx_cli_username + ":" + $VMDeploymentConfig.NSXManager.nsx_passwd_0)
)
$head = @{
    Authorization = "Basic $auth"
    "Content-Type" = "application/json"
}

# Accept EULA
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/eula/accept"
    Method = "POST"
    head = $head
}
$Result = Invoke-WebRequest @CmdletParams

# Fetch current telemetry configuration to retrieve revision
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/telemetry/config"
    Method = "GET"
    head = $head
}
$Result = Invoke-WebRequest @CmdletParams
$Revision = ($Result.Content | ConvertFrom-Json)._revision

# Turn off CEIP and Telemetry
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/telemetry/config"
    Method = "PUT"
    head = $head
    body = @"
{
  "ceip_acceptance" : true,
  "schedule_enabled" : false,
  "_revision" : $Revision
}
"@
}
$Result = Invoke-WebRequest @CmdletParams

# Add License Key
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/licenses"
    Method = "POST"
    head = $head
    body = @"
{
    "license_key": "$($LicenseKey.NSXT)"
}
"@
}
$Result = Invoke-WebRequest @CmdletParams

# Add a Compute Manager (vCenter)
$Request = [System.Net.Webrequest]::Create("https://$($VMDeploymentConfig.VCSA.Appliance.fqdn)")
$Request.GetResponse() | Out-Null
$Cert = $Request.ServicePoint.Certificate
$Bytes = $Cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert)
$CertTemp = (Join-Path -Path $Env:TMP -ChildPath "cert-temp")
Set-Content -Value $Bytes -Encoding Byte -Path $CertTemp
$Thumbprint = (Get-FileHash -Path $CertTemp -Algorithm SHA256).Hash
$Thumbprint = $Thumbprint -replace '(..(?!$))','$1:'
Remove-Item -Path $CertTemp

$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/fabric/compute-managers"
    Method = "POST"
    head = $head
    body = @"
{
    "server": "$($VMDeploymentConfig.VCSA.Appliance.fqdn)",
    "origin_type": "vCenter",
    "credential" : {
        "credential_type" : "UsernamePasswordLoginCredential",
        "username": "$($VMDeploymentConfig.VCSA.Appliance.ssoaccount)",
        "password": "$($VMDeploymentConfig.VCSA.Appliance.ssopassword)",
        "thumbprint": "$($Thumbprint)"
    },
    "display_name": "$($VMDeploymentConfig.VCSA.Appliance.fqdn)",
    "create_service_account": true,
    "set_as_oidc_provider": true
}
"@
}
$Result = Invoke-WebRequest @CmdletParams
$ComputeManagerId = ($Result.Content | ConvertFrom-Json).id

# Wait for finishing Compute Manager registration
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/fabric/compute-managers/$($ComputeManagerId)/status"
    Method = "GET"
    head = $head
}
$Result = Invoke-WebRequest @CmdletParams

# Deploy remaining NSX Manager Nodes
$ComputeManagerStatus = ($Result.Content | ConvertFrom-Json)
if (($ComputeManagerStatus.connection_status -eq "UP") -and ($ComputeManagerStatus.registration_status -eq "REGISTERED")) {
    $CmdletParams = @{
        Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/cluster/nodes/deployments"
        Method = "POST"
        head = $head
        body = @"
{
  "deployment_requests": [
    {
      "deployment_config": {
        "allow_ssh_root_login": true,
        "compute_id": "domain-c8",
        "default_gateway_addresses":[
          "192.168.10.1"
        ],
        "dns_servers": [
          "192.168.10.9"
        ],
        "enable_ssh": true,
        "hostname": "nsxmgr02.rainpole.lab",
        "management_network_id": "dvportgroup-31",
        "management_port_subnets":[
          {
            "ip_addresses":[
              "192.168.10.52"
            ],
            "prefix_length": 24
          }
        ],
        "ntp_servers": [
          "0.kr.pool.ntp.org",
          "1.kr.pool.ntp.org",
          "2.kr.pool.ntp.org"
        ],
        "placement_type": "VsphereClusterNodeVMDeploymentConfig",
        "search_domains": [
          "rainpole.lab"
        ],
        "storage_id": "datastore-14",
        "vc_id": "$($ComputeManagerId)"
      },
      "form_factor": "MEDIUM",
      "roles": [
        "CONTROLLER",
        "MANAGER"
      ],
      "user_settings": {
        "audit_password": `"$($VMDeploymentConfig.NSXManager.nsx_cli_audit_passwd_0)`",
        "cli_password": `"$($VMDeploymentConfig.NSXManager.nsx_cli_passwd_0)`",
        "root_password": `"$($VMDeploymentConfig.NSXManager.nsx_passwd_0)`"
      }
    },
    {
      "deployment_config": {
        "allow_ssh_root_login": true,
        "compute_id": "domain-c8",
        "default_gateway_addresses":[
          "192.168.10.1"
        ],
        "dns_servers": [
          "192.168.10.9"
        ],
        "enable_ssh": true,
        "hostname": "nsxmgr03.rainpole.lab",
        "management_network_id": "dvportgroup-31",
        "management_port_subnets":[
          {
            "ip_addresses":[
              "192.168.10.53"
            ],
            "prefix_length": 24
          }
        ],
        "ntp_servers": [
          "0.kr.pool.ntp.org",
          "1.kr.pool.ntp.org",
          "2.kr.pool.ntp.org"
        ],
        "placement_type": "VsphereClusterNodeVMDeploymentConfig",
        "search_domains": [
          "rainpole.lab"
        ],
        "storage_id": "datastore-14",
        "vc_id": "$($ComputeManagerId)"
      },
      "form_factor": "MEDIUM",
      "roles": [
        "CONTROLLER",
        "MANAGER"
      ],
      "user_settings": {
        "audit_password": `"$($VMDeploymentConfig.NSXManager.nsx_cli_audit_passwd_0)`",
        "cli_password": `"$($VMDeploymentConfig.NSXManager.nsx_cli_passwd_0)`",
        "root_password": `"$($VMDeploymentConfig.NSXManager.nsx_passwd_0)`"
      }
    }
  ]
}
"@
    }
    $Result = Invoke-WebRequest @CmdletParams
}

# Assign Virtual IP to a Cluster
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/cluster/api-virtual-ip?action=set_virtual_ip&ip_address=192.168.10.50"
    Method = "POST"
    head = $head
}
$Result = Invoke-WebRequest @CmdletParams

# Generate a New Certificate Signing Request with Extensions
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/trust-management/csrs-extended"
    Method = "POST"
    head = $head
    body = @"
{
  "display_name": "nsxmgr.rainpole.lab",
  "subject": {
    "attributes": [
      {"key": "CN", "value": "nsxmgr.rainpole.lab"},
      {"key": "O", "value": "VMware Inc."},
      {"key": "OU", "value": "NSX"},
      {"key": "C", "value": "US"},
      {"key": "ST", "value": "CA"},
      {"key": "L", "value": "Palo Alto"}
    ]
  },
  "key_size": "2048",
  "algorithm": "RSA",
  "extensions": {
    "subject_alt_names": {
      "dns_names": [
        "nsxmgr.rainpole.lab"
      ],
      "ip_addresses": [
          "192.168.10.50"
      ]
    }
  }
}
"@
}
$Result = Invoke-WebRequest @CmdletParams
$CSRId = ($Result.Content | ConvertFrom-Json).id

# Self-Sign the CSR
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/trust-management/csrs/$($CSRId)?action=self_sign&days_valid=825"
    Method = "POST"
    head = $head
}
$Result = Invoke-WebRequest @CmdletParams
$CertificateId = ($Result.Content | ConvertFrom-Json).id

# Register the Self-Signed Certificate with the NSX-T Management Cluster Certificate API Server
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/cluster/api-certificate?action=set_cluster_certificate&certificate_id=$($CertificateId)"
    Method = "POST"
    head = $head
}
$Result = Invoke-WebRequest @CmdletParams

# Retrieve the host switch name from the transport zones
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/api/v1/transport-zones"
    Method = "GET"
    head = $head
}
$Result = Invoke-WebRequest @CmdletParams

# Create TEP IP Pool
$IPPoolName = "TEP-IP-POOL"
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/policy/api/v1/infra/ip-pools/$($IPPoolName)"
    Method = "PATCH"
    head = $head
    body = @"
{
  "display_name": "$($IPPoolName)",
  "description": "$($IPPoolName)"
}
"@
}
$Result = Invoke-WebRequest @CmdletParams

# Add a new IP Subnet to the TEP IP Pool (An IP Subnet cannot be created with an IP Pool, need to be created separately)
$IPSubnetName = "TEP-IP-POOL-IP-SUBNET"
$CmdletParams = @{
    Uri = "https://$($VMDeploymentConfig.NSXManager.nsx_hostname)/policy/api/v1/infra/ip-pools/$($IPPoolName)/ip-subnets/$($IPSubnetName)"
    Method = "PATCH"
    head = $head
    body = @"
{
  "display_name": "$($IPSubnetName)",
  "resource_type": "IpAddressPoolStaticSubnet",
  "cidr": "192.168.40.0/24",
  "allocation_ranges": [
    {
      "start": "192.168.40.11",
      "end": "192.168.40.20"
    }
  ]
}
"@
}
$Result = Invoke-WebRequest @CmdletParams
