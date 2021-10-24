# PowerShell Module for VMware Cloud Notifications

![](vmware-cloud-ngw-icon.png)

## Summary

PowerShell Module to interact with the [VMware Cloud Notification Gateway](https://cloud.vmware.com/community/2020/03/26/day2experience/) API. More details can be found in this blog post [here](https://www.virtuallyghetto.com/2020/06/extending-vmware-cloud-on-aws-notifications-using-the-notification-gateway-api.html).

## Prerequisites
* [PowerCLI 12.0](https://code.vmware.com/web/tool/12.0.0/vmware-powercli) or newer
* VMware Cloud on AWS scoped [Refresh Token](https://docs.vmware.com/en/VMware-Cloud-services/services/Using-VMware-Cloud-Services/GUID-E2A3B1C1-E9AD-4B00-A6B6-88D31FCDDF7C.html)

## Functions

* Connect-VmcNotification
* Get-VmcNotificationEvent
* Get-VmcNotificationWebhook
* New-VmcNotificationWebhook
* Remove-VmcNotificationWebhook
* Test-VmcNotificationWebhook
* Get-VmcNotificationType
* Get-VmcNotificationCategory
* Get-VmcNotificationPreference
* Set-VmcNotificationPreference