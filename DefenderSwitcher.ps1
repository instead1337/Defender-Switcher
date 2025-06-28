param ([switch]$enable_av, [switch]$disable_av)
$interactiveMode = (!$enable_av -and !$disable_av)

# Acquiring the highest privileges
function RunAsTI ($cmd,$arg) { $id='RunAsTI'; $key="Registry::HKU\$(((whoami /user)-split' ')[-1])\Volatile Environment"; $code=@'
 $I=[int32]; $M=$I.module.gettype("System.Runtime.Interop`Services.Mar`shal"); $P=$I.module.gettype("System.Int`Ptr"); $S=[string]
 $D=@(); $T=@(); $DM=[AppDomain]::CurrentDomain."DefineDynami`cAssembly"(1,1)."DefineDynami`cModule"(1); $Z=[uintptr]::size 
 0..5|% {$D += $DM."Defin`eType"("AveYo_$_",1179913,[ValueType])}; $D += [uintptr]; 4..6|% {$D += $D[$_]."MakeByR`efType"()}
 $F='kernel','advapi','advapi', ($S,$S,$I,$I,$I,$I,$I,$S,$D[7],$D[8]), ([uintptr],$S,$I,$I,$D[9]),([uintptr],$S,$I,$I,[byte[]],$I)
 0..2|% {$9=$D[0]."DefinePInvok`eMethod"(('CreateProcess','RegOpenKeyEx','RegSetValueEx')[$_],$F[$_]+'32',8214,1,$S,$F[$_+3],1,4)}
 $DF=($P,$I,$P),($I,$I,$I,$I,$P,$D[1]),($I,$S,$S,$S,$I,$I,$I,$I,$I,$I,$I,$I,[int16],[int16],$P,$P,$P,$P),($D[3],$P),($P,$P,$I,$I)
 1..5|% {$k=$_; $n=1; $DF[$_-1]|% {$9=$D[$k]."Defin`eField"('f' + $n++, $_, 6)}}; 0..5|% {$T += $D[$_]."Creat`eType"()}
 0..5|% {nv "A$_" ([Activator]::CreateInstance($T[$_])) -fo}; function F ($1,$2) {$T[0]."G`etMethod"($1).invoke(0,$2)}   
 $TI=(whoami /groups)-like'*1-16-16384*'; $As=0; if(!$cmd) {$cmd='control';$arg='admintools'}; if ($cmd-eq'This PC'){$cmd='file:'}
 if (!$TI) {'TrustedInstaller','lsass','winlogon'|% {if (!$As) {$9=sc.exe start $_; $As=@(get-process -name $_ -ea 0|% {$_})[0]}}
 function M ($1,$2,$3) {$M."G`etMethod"($1,[type[]]$2).invoke(0,$3)}; $H=@(); $Z,(4*$Z+16)|% {$H += M "AllocHG`lobal" $I $_}
 M "WriteInt`Ptr" ($P,$P) ($H[0],$As.Handle); $A1.f1=131072; $A1.f2=$Z; $A1.f3=$H[0]; $A2.f1=1; $A2.f2=1; $A2.f3=1; $A2.f4=1
 $A2.f6=$A1; $A3.f1=10*$Z+32; $A4.f1=$A3; $A4.f2=$H[1]; M "StructureTo`Ptr" ($D[2],$P,[boolean]) (($A2 -as $D[2]),$A4.f2,$false)
 $Run=@($null, "powershell -win 1 -nop -c iex `$env:R; # $id", 0, 0, 0, 0x0E080600, 0, $null, ($A4 -as $T[4]), ($A5 -as $T[5]))
 F 'CreateProcess' $Run; return}; $env:R=''; rp $key $id -force; $priv=[diagnostics.process]."GetM`ember"('SetPrivilege',42)[0]   
 'SeSecurityPrivilege','SeTakeOwnershipPrivilege','SeBackupPrivilege','SeRestorePrivilege' |% {$priv.Invoke($null, @("$_",2))}
 $HKU=[uintptr][uint32]2147483651; $NT='S-1-5-18'; $reg=($HKU,$NT,8,2,($HKU -as $D[9])); F 'RegOpenKeyEx' $reg; $LNK=$reg[4]
 function L ($1,$2,$3) {sp 'HKLM:\Software\Classes\AppID\{CDCBCFCA-3CDC-436f-A4E2-0E02075250C2}' 'RunAs' $3 -force -ea 0
  $b=[Text.Encoding]::Unicode.GetBytes("\Registry\User\$1"); F 'RegSetValueEx' @($2,'SymbolicLinkValue',0,6,[byte[]]$b,$b.Length)}
 function Q {[int](gwmi win32_process -filter 'name="explorer.exe"'|?{$_.getownersid().sid-eq$NT}|select -last 1).ProcessId}
 $11bug=($((gwmi Win32_OperatingSystem).BuildNumber)-eq'22000')-AND(($cmd-eq'file:')-OR(test-path -lit $cmd -PathType Container))
 if ($11bug) {'System.Windows.Forms','Microsoft.VisualBasic' |% {[Reflection.Assembly]::LoadWithPartialName("'$_")}}
 if ($11bug) {$path='^(l)'+$($cmd -replace '([\+\^\%\~\(\)\[\]])','{$1}')+'{ENTER}'; $cmd='control.exe'; $arg='admintools'}
 L ($key-split'\\')[1] $LNK ''; $R=[diagnostics.process]::start($cmd,$arg); if ($R) {$R.PriorityClass='High'; $R.WaitForExit()}
 if ($11bug) {$w=0; do {if($w-gt40){break}; sleep -mi 250;$w++} until (Q); [Microsoft.VisualBasic.Interaction]::AppActivate($(Q))}
 if ($11bug) {[Windows.Forms.SendKeys]::SendWait($path)}; do {sleep 7} while(Q); L '.Default' $LNK 'Interactive User'
'@; $V='';'cmd','arg','id','key'|%{$V+="`n`$$_='$($(gv $_ -val)-replace"'","''")';"}; sp $key $id $($V,$code) -type 7 -force -ea 0
 start powershell -args "-win 1 -nop -c `n$V `$env:R=(gi `$key -ea 0).getvalue(`$id)-join''; iex `$env:R" -verb runas
} # lean & mean snippet by AveYo, 2022.01.28

$arg = ( 
    ($PSBoundParameters.GetEnumerator() |
        ForEach-Object {
            if ($_.Value -is [switch] -and $_.Value.IsPresent) {"-$($_.Key)"}
            elseif ($_.Value -isnot [switch]) {"-$($_.Key) `"$($_.Value -replace '"','""')`""}
        }
    ) + 
    ($args | % {"`"$($_ -replace '"','""')`""})
) -join ' '

if (!(whoami /user | findstr "S-1-5-18").Length -gt 0) {
    $exe = if ($PSVersionTable.PSVersion.Major -gt 5) {"pwsh.exe"} else {"powershell.exe"}
    $script = if ($MyInvocation.PSCommandPath) {$MyInvocation.PSCommandPath} else {$PSCommandPath}
    RunAsTI $exe "-NoP -EP Bypass -File `"$script`" $arg"
    exit
}

# Check system integrity
function CheckSystemIntegrity {
    function HandleError {
        param ($message)
        Write-Host "Error: $message" -F Red
        pause
        if ((Read-Host "Do you want to run 'sfc /scannow' for system recovery? (Y/N)") -match '^(Y|y)$') {
            Write-Host "Starting system scan..." -F Yellow
            [Diagnostics.Process]::Start("cmd.exe","/c sfc /scannow & pause").WaitForExit()
        } else {
            Write-Host "Skipping. Consider reinstalling Windows" -F Red
            pause
        }
        exit
    }

    $ErrorActionPreference = 'SilentlyContinue'

    if (!(gcm Add-WindowsPackage -EA 0)) {
        if (!(Test-Path "C:\Windows\System32\WindowsPowerShell\v1.0\Modules")) {
            HandleError "Modules directory missing"
        } else {
            HandleError "Add-WindowsPackage not found"
        }
    }

    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide' | % {if (!(Test-Path $_)) {HandleError "Missing: $_"}}

    'TrustedInstaller','wuauserv','bits','cryptsvc' | % {if (!(gsv $_ -EA 0)) {HandleError "Missing service: $_"}}

    $ErrorActionPreference = 'Continue'
}

# Prerequisite
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class ConsoleManager {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetStdHandle(int nStdHandle);
    [DllImport("kernel32.dll")]
    public static extern bool SetCurrentConsoleFontEx(IntPtr hConsoleOutput, bool bMaximumWindow, ref CONSOLE_FONT_INFO_EX lpConsoleCurrentFontEx);
    [DllImport("kernel32.dll")]
    public static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);
    [DllImport("kernel32.dll")]
    public static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
    [DllImport("user32.dll", CharSet=CharSet.Auto, SetLastError=true)]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)]
    public struct CONSOLE_FONT_INFO_EX {
        public uint cbSize;
        public uint nFont;
        public COORD dwFontSize;
        public int FontFamily;
        public int FontWeight;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst=32)]
        public string FaceName;
    }
    [StructLayout(LayoutKind.Sequential)]
    public struct COORD {public short X; public short Y;}
    [StructLayout(LayoutKind.Sequential)]
    public struct RECT {public int Left; public int Top; public int Right; public int Bottom;}
    public const int STD_OUTPUT_HANDLE = -11;
    public static void ResizeWindow(int w, int h) {
        MoveWindow(GetConsoleWindow(), 0, 0, w, h, true);
    }
    public static void SetConsoleFont(string name, short size) {
        CONSOLE_FONT_INFO_EX info = new CONSOLE_FONT_INFO_EX();
        info.cbSize = (uint)Marshal.SizeOf(typeof(CONSOLE_FONT_INFO_EX));
        info.FaceName = name;
        info.dwFontSize = new COORD {X = size, Y = size};
        info.FontFamily = 54;
        info.FontWeight = 400;
        SetCurrentConsoleFontEx(GetStdHandle(STD_OUTPUT_HANDLE), false, ref info);
    }
    public static void QuickEditOFF() {
        IntPtr hConIn = GetStdHandle(-10);
        uint m;
        if (GetConsoleMode(hConIn, out m))
            SetConsoleMode(hConIn, (m | 0x80U) & ~0x40U);
    }
    public static void QuickEditON() {
        IntPtr hConIn = GetStdHandle(-10);
        uint m;
        if (GetConsoleMode(hConIn, out m))
            SetConsoleMode(hConIn, (m | 0x40U) & ~0x80U);
    }
}
"@

function AdjustDesign {
    Add-Type -AssemblyName System.Windows.Forms
    $host.PrivateData.WarningBackgroundColor = 'Black'
    $host.PrivateData.ErrorBackgroundColor   = 'Black'
    $host.PrivateData.VerboseBackgroundColor = 'Black'
    $host.PrivateData.DebugBackgroundColor   = 'Black'
    $host.UI.RawUI.BackgroundColor = [ConsoleColor]::Black
    $host.UI.RawUI.ForegroundColor = [ConsoleColor]::White

    [ConsoleManager]::QuickEditOFF()
    [ConsoleManager]::ResizeWindow(850,550)
    [ConsoleManager]::SetConsoleFont("Consolas",16)
    $hwnd = [ConsoleManager]::GetConsoleWindow()
    $rect = New-Object ConsoleManager+RECT
    [ConsoleManager]::GetWindowRect($hwnd, [ref]$rect) *>$null

    $sw = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width
    $sh = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height
    $ww = $rect.Right - $rect.Left
    $wh = $rect.Bottom - $rect.Top
    $newX = [Math]::Max(0, [Math]::Round(($sw - $ww) / 2))
    $newY = [Math]::Max(0, [Math]::Round(($sh - $wh) / 2))
    [ConsoleManager]::MoveWindow($hwnd, $newX, $newY, $ww, $wh, $true) *>$null
}

function Write-Block {
    [CmdletBinding()]
    param (
        [int]$Indent          = 0,
        [string]$Content      = '',
        [string]$Title        = '',
        [string]$Description  = '',
        [int]$TitleWidth      = 24,
        [string]$LeftBracket  = '[',
        [string]$RightBracket = ']',
        [string]$Separator    = ' | ',
        [string]$BracketColor = 'Green',
        [string]$ContentColor = 'White',
        [string]$TextColor    = 'White'
    )

    if (!$Content) {return}

    $spaces = ' ' * $Indent
    $line = if ($Description) {[String]::Format("{0,-$TitleWidth}", $Title) + $Separator + $Description} else {$Title}

    Write-Host -NoNewline "$spaces$LeftBracket" -F $BracketColor
    Write-Host -NoNewline $Content -F $ContentColor
    Write-Host -NoNewline "$RightBracket " -F $BracketColor
    Write-Host $line -F $TextColor
}

function CheckDefenderStatus {
    $packageResult = (Get-WindowsPackage -Online | ? {$_.PackageName -like '*AntiBlocker*'})
    $svcResult = (Get-Service -Name WinDefend -EA 0 | Select-Object -ExpandProperty StartType)
    $svcResult = $svcResult -replace "`r`n", ""

    if ($packageResult -or $svcResult -eq 'Disabled') {
        $global:status = "disabled"
    } else {
        $global:status = "enabled"
    }
}

$ping = & ping -n 2 google.com | Select-String "TTL="
$file = if (Test-Path "$env:WinDir\DefenderSwitcher") {gci "$env:WinDir\DefenderSwitcher" -Filter "*AntiBlocker*" -File} else {$null}
$programUsable = $false

switch ($true) {
    ($null -eq $file) {
        if ($ping) {
            $dir = "$env:WinDir\DefenderSwitcher"
            $name = "Z-RapidOS-AntiBlocker-Package31bf3856ad364e35amd641.0.0.0.cab"
            $dst = "$dir\$name"
            $url = "https://rapid-community.ru/downloads/$name"
            if (!(Test-Path $dir)) {ni $dir -ItemType Directory *>$null}
            curl.exe -s -o $dst $url >$null 2>&1
            if (Test-Path $dst) {$programUsable = $true}
        }
        break
    }
    default {
        $programUsable = $true
        $dir = "$env:WinDir\DefenderSwitcher"
        $name = "Z-RapidOS-AntiBlocker-Package31bf3856ad364e35amd641.0.0.0.cab"
        $dst = "$dir\$name"
        $url = "https://rapid-community.ru/downloads/$name"
        $tmp = "$env:TEMP\$name"
        curl.exe -s -o $tmp $url >$null 2>&1
        if ((Test-Path $tmp) -and (Test-Path $dst)) {
            $h1 = (Get-FileHash $tmp).Hash
            $h2 = (Get-FileHash $dst).Hash
            if ($h1 -ne $h2) {Move-Item $tmp $dst -Force} else {rm $tmp}
        }
        break
    }
}

function MainMenu {
    cls
    CheckDefenderStatus;
    Write-Host "`n`n`n`n"
    Write-Host "         ______________________________________________________________" -F DarkGray
    Write-Host ""
    Write-Host "                               Defender Switcher"
    Write-Host ""
    Write-Host "                                Current Status:" -F Yellow
    if ($status -eq "enabled")
    {Write-Host "                          Windows Defender is ENABLED" -F Green}
else{Write-Host "                          Windows Defender's DISABLED" -F Red}
    if ($programUsable -eq $true) 
    {Write-Host "                            Defender can be toggled" -F Green}
else{Write-Host "                            Connect to the Internet" -F Red}
    Write-Host "               __________________________________________________" -F DarkGray
    Write-Host ""
    Write-Host "                               Choose an option:" -F Yellow
    Write-Block -Content "1" -Title "Enable Windows Defender" -Description "Restore Protection" -Indent 15 -TitleWidth 24
    Write-Block -Content "2" -Title "Disable Windows Defender" -Description "Turn Off Protection" -Indent 15 -TitleWidth 24
    Write-Block -Content "3" -Title "Information" -Description "Useful Information" -Indent 15 -TitleWidth 24
    Write-Block -Content "4" -Title "Exit" -Description "Close Program" -Indent 15 -TitleWidth 24
    Write-Host ""
    Write-Host "               __________________________________________________" -F DarkGray
    Write-Host ""
    Write-Host "              Choose a menu option using your keyboard [1,2,3,4] :" -F Green
    Write-Host ""
    Write-Host "         ______________________________________________________________" -F DarkGray
    Write-Host ""

    [ConsoleManager]::QuickEditOFF()
    $host.UI.RawUI.KeyAvailable > $null 2>&1
    $choice = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').Character
    switch ($choice) {
        '1' {EnableDefender}
        '2' {DisableDefender}
        '3' {ShowInformation}
        '4' {Start-Sleep -Seconds 1; exit}
        default {MainMenu}
    }
}

function EnableDefender {
    cls
    CheckDefenderStatus;
    switch ($status) {
        "enabled" {
            Write-Block -Content "INFO" -Title "Defender is already enabled."
        }
        default {
            [ConsoleManager]::QuickEditON()
            Write-Block -Content "PROCESSING" -Title "Enabling Defender..."

            Write-Block -Content "INFO" -Title "Removing CAB..."
            $ProgressPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'
            Get-WindowsPackage -Online | ? {$_.PackageName -like '*AntiBlocker*'} | % {
                Remove-WindowsPackage -Online -PackageName $_.PackageName -NoRestart
            } *>$null
            $ProgressPreference = 'Continue'; $WarningPreference = 'Continue'

            Write-Block -Content "INFO" -Title "Removing RepairSrc..."
            $path = [Environment]::ExpandEnvironmentVariables("%WinDir%\DefenderSwitcher\WinSxS")
            if (Test-Path $path) {del $path -Recurse -Force -EA 0}
            $regKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing"
            if (Test-Path $regKey) {Remove-ItemProperty -Path $regKey -Name "LocalSourcePath" -EA 0}

            CheckDefenderStatus;
            switch ($status) {
                "enabled" {
                    Write-Block -Content "INFO" -Title "Defender has been enabled."
                }
                default {
                    Write-Block -Content "ERROR" -Title "Failed to enable Defender." -ContentColor "Red"
                    Write-Host ""
                    Write-Host "Try to reboot your PC and try again."
                    Write-Host "If error occurs, try to use program in safe boot with ethernet option."
                    Write-Host "If nothing helped, please, make an issue on GitHub or write in Rapid Community's discord server for help."
                }
            }
        }
    }
    if ($interactiveMode) {
        pause
        MainMenu
    } else {
        exit
    }
}

function DisableDefender {
    cls
    CheckDefenderStatus;
    switch ($status) {
        "disabled" {
            Write-Block -Content "INFO" -Title "Defender is already disabled."
        }
        default {
            [ConsoleManager]::QuickEditON()
            if ($programUsable -eq $true) {
                Write-Block -Content "PROCESSING" -Title "Disabling Defender..."

                ProcessDefender -InstallCAB $true
                ProcessDefender -LinkManifests $true

                CheckDefenderStatus;
                switch ($status) {
                    "disabled" {
                        Write-Block -Content "INFO" -Title "Defender has been disabled."
                    }
                    default {
                        Write-Block -Content "ERROR" -Title "Failed to disable Defender." -ContentColor "Red"
                        Write-Host ""
                        Write-Host "Try to reboot your PC and try again."
                        Write-Host "If error occurs, try to use program in safe boot with ethernet option."
                        Write-Host "If nothing helped, please, make an issue on GitHub or write in Rapid Community's discord server for help."
                    }
                }
            } else {
                Write-Block -Content "ERROR" -Title "Connect to the internet and restart Defender Switcher to proceed." -ContentColor "Red"
            }
        }
    }
    if ($interactiveMode) {
        pause
        MainMenu
    } else {
        exit
    }
}

function ProcessDefender {
    param([switch]$InstallCAB, [switch]$LinkManifests)

    if ($InstallCAB) {
        $item = gci "$env:WinDir\DefenderSwitcher" -Filter "*AntiBlocker*" -File
        if (!$item) {return}

        $path = $item.FullName
        $cert = (Get-AuthenticodeSignature $path).SignerCertificate
        if (!$cert -or $cert.Extensions.EnhancedKeyUsages.Value -ne "1.3.6.1.4.1.311.10.3.6") {return}

        $regKey = "HKLM:\Software\Microsoft\SystemCertificates\ROOT\Certificates\8A334AA8052DD244A647306A76B8178FA215F344"
        if (!(Test-Path $regKey)) {mkdir $regKey -Force *>$null}

        Write-Block -Content "INFO" -Title "Installing CAB..."
        $ProgressPreference = 'SilentlyContinue'
        try {
            Add-WindowsPackage -Online -PackagePath $path -NoRestart -IgnoreCheck -LogLevel 1 *>$null
        } catch {
            Write-Block -Content "INFO" -Title "Using DISM fallback..."
            DISM /Online /Add-Package /PackagePath:$path /NoRestart *>$null
        }
        $ProgressPreference = 'Continue'
    }

    if ($LinkManifests) {
        CheckDefenderStatus; if ($status -ne "disabled") {return}

        $version = '38655.38527.65535.65535'
        $src = [Environment]::ExpandEnvironmentVariables("%WinDir%\DefenderSwitcher\WinSxS")
        $list = gci "$env:WinDir\WinSxS\Manifests" -File -Filter "*$version*"
        if (!$list) {return}

        if (Test-Path $src) {del $src -Recurse -Force}
        mkdir "$src\Manifests" -Force *>$null

        Write-Block -Content "INFO" -Title "Linking manifests..."
        $list | % {New-Item -ItemType HardLink -Path "$src\Manifests\$($_.Name)" -Target $_.FullName *>$null}

        $regKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing"
        if (!(Test-Path $regKey)) {mkdir $regKey -Force *>$null}
        Set-ItemProperty -Path $regKey -Name "LocalSourcePath" -Value "%WinDir%\DefenderSwitcher\WinSxS" -Type ExpandString -Force
    }
}

function ShowInformation {
    cls
    Write-Host "`n`n`n"
    Write-Host "         ______________________________________________________________" -F DarkGray
    Write-Host ""
    Write-Host "                               Defender Switcher"
    Write-Host ""
    Write-Host "               Credits:" -F Yellow
    Write-Host ""
    Write-Block -Content "1" -Title "AtlasOS CAB Method" -Indent 15
    Write-Block -Content "2" -Title "AveYo's TI Elevation" -Indent 15
    Write-Block -Content "3" -Title "MAS-Based Design" -Indent 15
    Write-Host ""
    Write-Host "               __________________________________________________" -F DarkGray
    Write-Host ""
    Write-Host "               Our links:" -F Yellow
    Write-Host ""
    Write-Block -Content "4" -Title "GitHub" -Indent 15
    Write-Block -Content "5" -Title "Discord" -Indent 15
    Write-Block -Content "6" -Title "Website" -Indent 15
    Write-Host ""
    Write-Host "               __________________________________________________" -F DarkGray
    Write-Host ""
    Write-Host "           Choose a menu option using your keyboard [1,2,3,4,5,6,q] :" -F Green
    Write-Host ""
    Write-Host "         ______________________________________________________________" -F DarkGray
    $choice = ""
    while ($choice -ne 'q') {
        $choice = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').Character
        switch ($choice) {
            '1' {Start-Process "https://github.com/Atlas-OS/Atlas"}
            '2' {Start-Process "https://github.com/AveYo/LeanAndMean"}
            '3' {Start-Process "https://github.com/massgravel/Microsoft-Activation-Scripts"}
            '4' {Start-Process "https://github.com/instead1337/Defender-Switcher"}
            '5' {Start-Process "https://dsc.gg/rapid-community"}
            '6' {Start-Process "https://rapid-community.ru"}
            'q' {MainMenu}
        }
    }
}

if ($enable_av) {EnableDefender}
if ($disable_av) {DisableDefender}
if ($interactiveMode) {CheckSystemIntegrity; AdjustDesign; MainMenu} else {exit}