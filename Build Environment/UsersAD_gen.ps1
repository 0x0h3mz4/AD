param([Parameter(Mandatory = $true)]$JSONFile)

function CreateADGroup {
    param (
        [Parameter(Mandatory = $true)] $grouPbject)
    $name = $grouPbject.name
    New-ADGroup -name $name -GroupScope Global
}
function CreateADUser {
    param (
        [Parameter(Mandatory = $true)] $userObject
    )
    $name = $userObject.name
    $password = $userObject.password
    if ($name -ne $null) {
        $firstname = $name.split(" ")[0]
        $lastname = $name.split(" ")[1]
        $username = $firstname[0] + $lastname
        $SamAccountName = $username.ToLower()
        $principalname = $username.ToLower()
    }
    $Global:Domain = $json.domain
    if ($password -ne $null) {
        New-ADUser -Name $name -GivenName $firstname -Surname $lastname -SamAccountName $SamAccountName -UserPrincipalName $principalname@$Global:Domain -AccountPassword (ConvertTo-SecureString $password -AsPlainText -Force) -PassThru | Enable-ADAccount
    }
    foreach ($group_name in $userObject.groups) {
        try {
            Get-ADComputer -Identity "$group_name"
            Add-ADGroupMember -Identity $group_name -Members $username
        }
        catch [Microsoft.ActiveDirectory.Management.ADIdentityResolutionException] {
            Write-Warning "AD group object not found"
        }
        Add-ADGroupMember -Identity $group_name -Members $username
    }


    
}

$json = Get-Content $JSONFile | ConvertFrom-Json

foreach ($group in $json.groups) {
    CreateADGroup $group
}

foreach ($user in $json.users) {
    CreateADUser $user
}
