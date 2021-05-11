Function Connect-VmcNotification {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          06/08/2020
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Connect to VMC Notification service API
    .DESCRIPTION
        This cmdlet creates $global:vmcNotificationGWConnection object containing the VMC Notification URL along with CSP Token
    .EXAMPLE
        Connect-VmcNotification -RefreshToken $RefreshToken -OrgName $OrgName
    .NOTES
        You must be logged into VMC using Connect-VmcServer cmdlet
#>
    Param (
        [Parameter(Mandatory=$true)][String]$RefreshToken,
        [Parameter(Mandatory=$true)][String]$OrgName
    )

    If (-Not $global:DefaultVMCServers.IsConnected) { Write-error "No valid VMC Connection found, please use the Connect-VMC to connect"; break } Else {
        $orgId = (Get-VmcOrganization | where {$_.Name -eq $OrgName}).Id
    }

    $results = Invoke-WebRequest -Uri "https://console.cloud.vmware.com/csp/gateway/am/api/auth/api-tokens/authorize" -Method POST -Headers @{accept='application/json'} -Body "refresh_token=$RefreshToken"
    if($results.StatusCode -ne 200) {
        Write-Host -ForegroundColor Red "Failed to retrieve Access Token, please ensure your VMC Refresh Token is valid and try again"
        break
    }
    $accessToken = ($results | ConvertFrom-Json).access_token

    $headers = @{
        "csp-auth-token"="$accessToken"
        "Content-Type"="application/json"
        "Accept"="application/json"
    }
    $global:vmcNotificationGWConnection = new-object PSObject -Property @{
        'Server' = "https://vmc.vmware.com/vmc/ng/api/orgs/${orgId}"
        'headers' = $headers
    }
    $global:vmcNotificationGWConnection
}

Function Get-VmcNotificationEvent {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          06/08/2020
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        List all VMC Notification events that can be subscribed to via webhook
    .DESCRIPTION
        List all VMC Notification events that can be subscribed to via webhook
    .EXAMPLE
        Get-VmcNotificationEvent
#>
    Param (
        [Parameter(Mandatory=$False)]$Name,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vmcNotificationGWConnection) { Write-error "No VMC Notification Connection found, please use Connect-VmcNotification" } Else {
        $method = "GET"
        $webhookURL = $global:vmcNotificationGWConnection.Server + "/webhooks/events"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$webhookURL`n"
        }

        try {
            if($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri $webhookURL -Method $method -Headers $global:vmcNotificationGWConnection.headers -SkipCertificateCheck
            } else {
                $requests = Invoke-WebRequest -Uri $webhookURL -Method $method -Headers $global:vmcNotificationGWConnection.headers
            }
        } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
                break
            } else {
                Write-Error "Error in retrieving VMC Notification Events"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
        }

        if($requests.StatusCode -eq 200) {
            ($requests.Content | ConvertFrom-Json)|Sort-Object -Property Id
        }
    }
}

Function Get-VmcNotificationWebhook {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          06/08/2020
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Retrieve all VMC Notification webhooks that have been created
    .DESCRIPTION
        Retrieve all VMC Notification webhooks that have been created
    .EXAMPLE
        Get-VmcNotificationWebhook
#>
    Param (
        [Parameter(Mandatory=$False)]$Id,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vmcNotificationGWConnection) { Write-error "No VMC Notification Connection found, please use Connect-VmcNotification" } Else {
        $method = "GET"
        $webhookURL = $global:vmcNotificationGWConnection.Server + "/webhooks"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$webhookURL`n"
        }

        try {
            if($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri $webhookURL -Method $method -Headers $global:vmcNotificationGWConnection.headers -SkipCertificateCheck
            } else {
                $requests = Invoke-WebRequest -Uri $webhookURL -Method $method -Headers $global:vmcNotificationGWConnection.headers
            }
        } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
                break
            } else {
                Write-Error "Error in retrieving VMC Notification Webhooks"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
        }

        if($requests.StatusCode -eq 200) {
            $results = ($requests.Content | ConvertFrom-Json)

            if($results -eq $NULL) {
                break
            }

            if ($PSBoundParameters.ContainsKey("Id")){
                $results = $results | where {$_.id -eq $Id}
            }

            $webhooks = @()
            foreach ($result in $results) {
                $tmp = [pscustomobject] @{
                    id = $result.id;
                    client_id = $result.client_id;
                    status = $result.status;
                    createdBy = $result.user_name;
                    webhookURL = $result.web_hook_info.callback_uri;
                    webhookHeaders = $result.web_hook_info.callback_headers;
                    webhookBody = $result.web_hook_info.template;
                    subscribed_events = $result.web_hook_info.subscribed_events;
                    subscribed_events_filter = $result.web_hook_info.subscribe_filter;
                }
                $webhooks += $tmp
            }
            $webhooks
        }
    }
}

Function New-VmcNotificationWebhook {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          06/08/2020
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Create a new VMC Notification webhook
    .DESCRIPTION
        Create a new VMC Notification webhook
    .EXAMPLE
        $vmcSlackNotificationParams = @{
            ClientId = "vmc-sddc-slack-notification";
            WebhookURL = "https://hooks.slack.com/services/FILL-ME-IN";
            NotificationEvents = @("SDDC-PROVISION","SDDC-DELETE");
        }

        New-VmcNotificationWebhook @vmcSlackNotificationParams
#>
    Param (
        [Parameter(Mandatory=$true)]$ClientId,
        [Parameter(Mandatory=$true)]$WebhookURL,
        [Parameter(Mandatory=$false)]$WebhookHeaders,
        [Parameter(Mandatory=$false)]$WebhookBody,
        [Parameter(Mandatory=$false)][ValidateSet("ACTIVE","DISABLED")][string]$Status="ACTIVE",
        [Parameter(Mandatory=$true)][String[]]$NotificationEvents,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vmcNotificationGWConnection) { Write-error "No VMC Notification Connection found, please use Connect-VmcNotification" } Else {
        $payload = @{
            client_id = $ClientId;
            status = $Status;
            web_hook_info = @{
                callback_uri = $WebhookURL;
                subscribed_events = $NotificationEvents;
            }
        }

        if($WebhookHeaders -ne $NULL) {
            $payload.web_hook_info.Add("callback_headers",$WebhookHeaders)
        }

        if($WebhookBody -ne $NULL) {
            $payload.web_hook_info.Add("template",$WebhookBody)
        }

        $body = $payload | ConvertTo-Json -depth 4

        $method = "POST"
        $newWebhookURL = $global:vmcNotificationGWConnection.Server + "/webhooks"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$newWebhookURL`n"
            Write-Host -ForegroundColor cyan "[DEBUG]`n$body`n"
        }

        try {
            if($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri $newWebhookURL -Body $body -Method $method -Headers $global:vmcNotificationGWConnection.headers  -SkipCertificateCheck
            } else {
                $requests = Invoke-WebRequest -Uri $newWebhookURL -Body $body -Method $method -Headers $global:vmcNotificationGWConnection.headers
            }
        } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
                break
            } else {
                Write-Error "Error in creating new VMC Notification Webhook"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
        }

        if($requests.StatusCode -eq 200) {
            ($requests.Content | ConvertFrom-Json)
        }
    }
}

Function Remove-VmcNotificationWebhook {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          06/08/2020
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Remove VMC Notification webhook
    .DESCRIPTION
        Remove VMC Notification webhook
    .EXAMPLE
        Remove-VmcNotificationWebhook -Id <WebhookID>
#>
    Param (
        [Parameter(Mandatory=$true)]$Id,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vmcNotificationGWConnection) { Write-error "No VMC Notification Connection found, please use Connect-VmcNotification" } Else {
        $method = "DELETE"
        $deleteWebhookURL = $global:vmcNotificationGWConnection.Server + "/webhooks/${Id}"
    }

    if($Troubleshoot) {
        Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$deleteWebhookURL`n"
        Write-Host -ForegroundColor cyan "[DEBUG]`n$body`n"
    }

    try {
        if($PSVersionTable.PSEdition -eq "Core") {
            $requests = Invoke-WebRequest -Uri $deleteWebhookURL -Method $method -Headers $global:vmcNotificationGWConnection.headers -SkipCertificateCheck
        } else {
            $requests = Invoke-WebRequest -Uri $deleteWebhookURL -Method $method -Headers $global:vmcNotificationGWConnection.headers
        }
    } catch {
        if($_.Exception.Response.StatusCode -eq "Unauthorized") {
            Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
            break
        } else {
            Write-Error "Error in deleting VMC Notification Webhooks"
            Write-Error "`n($_.Exception.Message)`n"
            break
        }
    }
}

Function Test-VmcNotificationWebhook {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          06/08/2020
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Test VMC Notification webhook configuration and connectivity
    .DESCRIPTION
        Test VMC Notification webhook configuration and connectivity
    .EXAMPLE
        Test-VmcNotificationWebhook -Id <WebhookID> -EventId "SDDC-PROVISION"
#>
    Param (
        [Parameter(Mandatory=$true)]$Id,
        [Parameter(Mandatory=$true)]$EventId,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vmcNotificationGWConnection) { Write-error "No VMC Notification Connection found, please use Connect-VmcNotification" } Else {
        $payload = @{
            event_id = $EventId;
            description = "Example notification description";
            display_name = "VMC Notification Test";
            send_date_time = "2019-11-05T12:40:00.763000Z";
            client_id = "VMC-Notification-123";
            org_id = "dd768999-d80a-41e1-adc6-b7436506566e";
            org_name = "VMC-Customer[0]";
            text = "Test Message";
            message = @{
                id = "dd768999-d80a-41e1-adc6-b7436506566e";
                created = "2019-11-05T12:39:45.000811Z";
                sent = "";
                failed = "";
                valid_to = "2019-11-12T12:39:45.411+0000";
                canceled_date = "";
                tenant_id =  "39e7b934-ea33-431c-81f1-91de2822b795";
                notification_id = "f855f8d8-52d1-4ae6-8769-b2b49252fec4";
                priority = "NORMAL";
                severity = "INFO";
                title = "Test Notification";
                text = "Test Message";
                state = "PREPARED";
                cc = @();
                resource_type = "ORG";
                resource_id = "39e7b934-ea33-431c-81f1-91de2822b795";
                resource_name = "PROD-SDDC-01";
                user_name = "admin@vmware.com";
                updated_by_user_name = "admin@vmware.com";
                updated =  "2019-11-05T12:39:45.000000Z";
            }
        }

        $body = $payload | ConvertTo-Json -depth 4

        $method = "POST"
        $testWebhookURL = $global:vmcNotificationGWConnection.Server + "/webhooks/${id}?action=simulate-event"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $method`n$testWebhookURL`n"
            Write-Host -ForegroundColor cyan "[DEBUG]`n$body`n"
        }

        try {
            if($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri $testWebhookURL -Body $body -Method $method -Headers $global:vmcNotificationGWConnection.headers -SkipCertificateCheck -TimeoutSec 5
            } else {
                $requests = Invoke-WebRequest -Uri $testWebhookURL -Body $body -Method $method -Headers $global:vmcNotificationGWConnection.headers -TimeoutSec 5
            }
        } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
                break
            } else {
                Write-Error "Error in sending test VMC Notification Webhook"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
        }

        if($requests.StatusCode -eq 200) {
            if( ($requests.Content | ConvertFrom-Json).web_hook_response -ne "OK") {
                Write-Host -ForegroundColor Red "Successfully sent test webhook but did not get acknowledgement"
            } else {
                Write-Host -ForegroundColor Green "Successfully sent test webhook and recieved acknowledgement"
            }
        }
    }
}