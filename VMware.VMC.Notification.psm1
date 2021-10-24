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
        'Server2' = "https://vmc.vmware.com/api/notification/${orgId}"
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
    .EXAMPLE
        $vmcVebaWebhookNotificationParams = @{
            ClientId = "vmc-veba-webhook-notification";
            WebhookURL = "https://veba.vmware.com/webhook";
            WebhookHeaders = @{
                "Content-Type" = 'application/cloudevents+json'
                "Authorization" = "Basic XXX"
            };
            WebhookBody = @{
                "id" = "{message.notification_id}"
                "type" = "vmware.vmc.{event_id}.v0"
                "source" = "https://vmc.vmware.com/console/sddcs/aws/{org_id}"
                "specversion" = "1.0"
                "datacontenttype" = "application/json"
                "data" = [ordered]@{
                    "org_id" = "{org_id}"
                    "org_name" = "{org_name}"
                    "resource_id" = "{message.resource_id}"
                    "resource" = "{message.resource_type}"
                    "resource_name" = "{message.resource_name}"
                    "message_username" = "{message.user_name}"
                    "message" = "{message.text}"
                }
            };
            NotificationEvents = @("SDDC-PROVISION","SDDC-DELETE");
        }
        New-VmcNotificationWebhook @vmcVebaWebhookNotificationParams -Troubleshoot
}
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

        # Body must be JSON encoded string
        $templateBody = (($WebhookBody | ConvertTo-Json -depth 4).replace(" ", "") -replace "\n", "")

        if($WebhookBody -ne $NULL) {
            $payload.web_hook_info.Add("template",$templateBody)
        }

        $body = $payload | ConvertTo-Json -depth 10

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

Function Get-VmcNotificationType {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          10/23/2021
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Retrieve all VMC Notification types
    .DESCRIPTION
        Retrieve all VMC Notification types
    .EXAMPLE
        Get-VmcNotificationType
    .EXAMPLE
        Get-VmcNotificationType -CategoryId SDDC_Maintenance
#>
    Param (
        [Parameter(Mandatory=$false)]$CategoryId,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vmcNotificationGWConnection) { Write-error "No VMC Notification Connection found, please use Connect-VmcNotification" } Else {
        $method = "GET"

        if($CategoryId) {
            $notifTypesURL = $global:vmcNotificationGWConnection.Server2 + "/notification-types?category=${CategoryId}" #system default is page=0 with size=50
        } else {
            $notifTypesURL = $global:vmcNotificationGWConnection.Server2 + "/notification-types" #system default is page=0 with size=50
        }

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$notifTypesURL"
        }

        try {
            if($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri $notifTypesURL -Method $method -Headers $global:vmcNotificationGWConnection.headers -SkipCertificateCheck
            } else {
                $requests = Invoke-WebRequest -Uri $notifTypesURL -Method $method -Headers $global:vmcNotificationGWConnection.headers
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
            $initialNotificationTypeResults = ($requests.Content | ConvertFrom-Json)

            $totalNotificationPages = $initialNotificationTypeResults.total_pages
            $totalNotificationCount = $initialNotificationTypeResults.total_elements

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] totalNotificationCount = $totalNotificationCount"
            }

            $totalNotifications = $initialNotificationTypeResults.content
            $seenNotifications = $totalNotifications.count

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] (currentCount = $seenNotificationss)"
            }

            $currentPage = 0
            while ( $currentPage -lt $totalNotificationPages) {
                $currentPage = $currentPage + 1

                if($CategoryId) {
                    $newNotifTypesURL = $notifTypesURL + "?category=${CategoryId}&page=$currentPage&size=50" # page=currentPage+1 & size=50 (match initial default)
                } else {
                    $newNotifTypesURL = $notifTypesURL + "?page=$currentPage&size=50" # page=currentPage+1 & size=50 (match initial default)
                }

                $newNotifTypesURL = $notifTypesURL + "?page=$currentPage&size=50" # page=currentPage+1 & size=50 (match initial default)

                if($Troubleshoot) {
                    Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$newNotifTypesURL`n"
                }

                try {
                    if($PSVersionTable.PSEdition -eq "Core") {
                        $requests = Invoke-WebRequest -Uri $newNotifTypesURL -Method $method -Headers $global:vmcNotificationGWConnection.headers -SkipCertificateCheck
                    } else {
                        $requests = Invoke-WebRequest -Uri $newNotifTypesURL -Method $method -Headers $global:vmcNotificationGWConnection.headers
                    }
                } catch {
                    if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                        Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
                        break
                    } else {
                        Write-Error "Error in retrieving VMC Notification Types"
                        Write-Error "`n($_.Exception.Message)`n"
                        break
                    }
                }

                $NotificationTypeResults = ($requests.Content | ConvertFrom-Json)
                $totalNotifications += $NotificationTypeResults.content
                $seenNotifications += $NotificationTypeResults.number_of_elements

                if($Troubleshoot) {
                    Write-Host -ForegroundColor cyan "`n[DEBUG] $newNotifTypesURL (currentCount = $seenNotifications)"
                }
            }
        }
    }

    $totalNotifications | Select Name, @{n="Id";e={$_.type}}, Category, Provider, Created, Updated
}

Function Get-VmcNotificationCategory {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          10/23/2021
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Retrieve all VMC Notification categories
    .DESCRIPTION
        Retrieve all VMC Notification categories
    .EXAMPLE
        Get-VmcNotificationCategory
#>
    Param (
        [Switch]$Troubleshoot
    )

    If (-Not $global:vmcNotificationGWConnection) { Write-error "No VMC Notification Connection found, please use Connect-VmcNotification" } Else {
        $method = "GET"

        $notifCatesURL = $global:vmcNotificationGWConnection.Server2 + "/notification-categories" #system default is page=0 with size=7

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$notifCatesURL"
        }

        try {
            if($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri $notifCatesURL -Method $method -Headers $global:vmcNotificationGWConnection.headers -SkipCertificateCheck
            } else {
                $requests = Invoke-WebRequest -Uri $notifCatesURL -Method $method -Headers $global:vmcNotificationGWConnection.headers
            }
        } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
                break
            } else {
                Write-Error "Error in retrieving VMC Notification Categories"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
        }

        if($requests.StatusCode -eq 200) {
            $initialNotificationCategoryResults = ($requests.Content | ConvertFrom-Json)

            $totalNotificationPages = $initialNotificationCategoryResults.total_pages
            $totalNotificationCount = $initialNotificationCategoryResults.total_elements

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] totalNotificationCount = $totalNotificationCount"
            }

            $totalNotificationCategories = $initialNotificationCategoryResults.content
            $seenNotificationCategories = $totalNotificationCategories.count

            if($Troubleshoot) {
                Write-Host -ForegroundColor cyan "`n[DEBUG] (currentCount = $seenNotificationss)"
            }

            $currentPage = 0
            while ( $currentPage -lt $totalNotificationPages) {
                $currentPage = $currentPage + 1

                $newNotifCatsURL = $notifTypesURL + "?page=$currentPage&size=7" # page=currentPage+1 & size=7 (match initial default)

                if($Troubleshoot) {
                    Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$newNotifCatsURL`n"
                }

                try {
                    if($PSVersionTable.PSEdition -eq "Core") {
                        $requests = Invoke-WebRequest -Uri $newNotifCatsURL -Method $method -Headers $global:vmcNotificationGWConnection.headers -SkipCertificateCheck
                    } else {
                        $requests = Invoke-WebRequest -Uri $newNotifCatsURL -Method $method -Headers $global:vmcNotificationGWConnection.headers
                    }
                } catch {
                    if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                        Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
                        break
                    } else {
                        Write-Error "Error in retrieving VMC Notification Categories"
                        Write-Error "`n($_.Exception.Message)`n"
                        break
                    }
                }

                $NotificationCategoryResults = ($requests.Content | ConvertFrom-Json)
                $totalNotificationCategories += $NotificationCategoryResults.content
                $seenNotificationCategories += $NotificationCategoryResults.number_of_elements

                if($Troubleshoot) {
                    Write-Host -ForegroundColor cyan "`n[DEBUG] $newNotifCatsURL (currentCount = $seenNotificationCategories)"
                }
            }
        }
    }
    $totalNotificationCategories | Select @{n="CategoryId";e={$_.Name}},@{n="CategoryName";e={$_.value}}
}

function Get-JWTtoken {
<#
    .DESCRIPTION
        Decodes a JWT token. This was taken from link below. Thanks to Vasil Michev!
    .LINK
        https://www.michev.info/Blog/Post/2140/decode-jwt-access-and-id-tokens-via-powershell
#>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True)]
        [string]$Token
    )

    #Validate as per https://tools.ietf.org/html/rfc7519
    #Access and ID tokens are fine, Refresh tokens will not work
    if (-not $Token.Contains(".") -or -not $Token.StartsWith("eyJ")) { Write-Error "Invalid token" -ErrorAction Stop }

    #Header
    $tokenheader = $Token.Split(".")[0].Replace('-', '+').Replace('_', '/')

    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenheader += "=" }

    #Payload
    $tokenPayload = $Token.Split(".")[1].Replace('-', '+').Replace('_', '/')

    #Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) { Write-Verbose "Invalid length for a Base-64 char array or string, adding ="; $tokenPayload += "=" }

    #Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload)

    #Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray)

    #Convert from JSON to PSObject
    $tokobj = $tokenArray | ConvertFrom-Json

    $tokobj
}

Function Get-VmcNotificationPreference {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          10/23/2021
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Retrieve current VMC Notification preferences
    .DESCRIPTION
        Retrieve current VMC Notification preferences
    .EXAMPLE
        Get-VmcNotificationPreference
    .EXAMPLE
        Get-VmcNotificationPreference -ExportFileName /Users/lamw/Desktop/notification-pref-lamw.json
#>
    Param (
        [Parameter(Mandatory=$false)]$ExportFileName,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vmcNotificationGWConnection) { Write-error "No VMC Notification Connection found, please use Connect-VmcNotification" } Else {
        $method = "GET"

        $notifPrefURL = ($global:vmcNotificationGWConnection.Server2 | Split-Path) + "/loggedin/user/preferences/categories?include=notification_types"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$notifPrefURL"
        }

        try {
            if($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri $notifPrefURL -Method $method -Headers $global:vmcNotificationGWConnection.headers -SkipCertificateCheck
            } else {
                $requests = Invoke-WebRequest -Uri $notifPrefURL -Method $method -Headers $global:vmcNotificationGWConnection.headers
            }
        } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
                break
            } else {
                Write-Error "Error in retrieving VMC Notification Preferences"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
        }

        if($requests.StatusCode -eq 200) {
            $categories = ($requests.Content | ConvertFrom-Json).categories

            $tmpResults = @()
            foreach ($category in $categories) {
                $tmp = [pscustomobject] @{
                    "name" = $category.name;
                    "channels" = $notificationType.channels;
                    "notification_types" = ($category.notification_types | Select name, channels);
                }
                $tmpResults += $tmp
            }

            $results = [pscustomobject] @{
                "categories" = $tmpResults
            }

            if($ExportFileName -eq $null) {
                $tokenUsername = (Get-JWTtoken -Token $global:vmcNotificationGWConnection.headers['csp-auth-token']).username
                $ExportFileName = "notification-pref-${tokenUsername}.json"

                Write-Host -ForegroundColor Green "Exporting ${tokenUsername} VMC Notification Preferences to ${ExportFileName} ..."
                $results | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $ExportFileName
            } else {
                Write-Host -ForegroundColor Green "Exporting ${tokenUsername} VMC Notification Preferences to ${ExportFileName} ..."
                $results | ConvertTo-Json -Depth 5 | Out-File -LiteralPath $ExportFileName
            }
        }
    }
}

Function Set-VmcNotificationPreference {
<#
    .NOTES
    ===========================================================================
    Created by:    William Lam
    Date:          10/23/2021
    Organization:  VMware
    Blog:          http://www.williamlam.com
    Twitter:       @lamw
    ===========================================================================

    .SYNOPSIS
        Update current VMC Notification preferences
    .DESCRIPTION
        Update current VMC Notification preferences
    .EXAMPLE
        Set-VmcNotificationPreference -ImportFileName notification-preference.json
#>
    Param (
        [Parameter(Mandatory=$true)]$ImportFileName,
        [Switch]$Troubleshoot
    )

    If (-Not $global:vmcNotificationGWConnection) { Write-error "No VMC Notification Connection found, please use Connect-VmcNotification" } Else {
        $method = "PATCH"

        $notifPrefURL = ($global:vmcNotificationGWConnection.Server2 | Split-Path) + "/loggedin/user/preferences/categories"

        if($Troubleshoot) {
            Write-Host -ForegroundColor cyan "`n[DEBUG] - $METHOD`n$notifPrefURL"
            Write-Host -ForegroundColor cyan "`n[DEBUG] - Body`n${ImportFileName}"
        }

        try {
            $json = Get-Content -Raw -LiteralPath $ImportFileName
        } catch {
            Write-Error "Failed to read ${ImportFileName}"
            break
        }

        try {
            if($PSVersionTable.PSEdition -eq "Core") {
                $requests = Invoke-WebRequest -Uri $notifPrefURL -Method $method -Headers $global:vmcNotificationGWConnection.headers -Body $json -SkipCertificateCheck
            } else {
                $requests = Invoke-WebRequest -Uri $notifPrefURL -Method $method -Headers $global:vmcNotificationGWConnection.headers
            }
        } catch {
            if($_.Exception.Response.StatusCode -eq "Unauthorized") {
                Write-Host -ForegroundColor Red "`nThe VMC Notification session is no longer valid, please re-run the Connect-VmcNotification cmdlet to retrieve a new token`n"
                break
            } else {
                Write-Error "Error in updating VMC Notification Preferences"
                Write-Error "`n($_.Exception.Message)`n"
                break
            }
        }

        if($requests.StatusCode -eq 204) {
            Write-Host -ForegroundColor Green "Successfully updated VMC Notification Preferences"
        }
    }
}