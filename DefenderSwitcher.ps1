param (
    [switch]$enable_av,
    [switch]$disable_av
)
$interactiveMode = (!$enable_av -and !$disable_av)

# Acquiring high privileges
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]'Administrator')) { $arguments = "-NoProfile -ExecutionPolicy Bypass -File `"{0}`"" -f $PSCommandPath, $MyArgument; Start-Process PowerShell.exe -ArgumentList $arguments -Verb RunAs; exit }
if (![Type]::GetType('Privileges')) {
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class Privileges {
    [DllImport("advapi32.dll")] internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);
    [DllImport("advapi32.dll")] internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)] internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    [StructLayout(LayoutKind.Sequential, Pack = 1)] internal struct TokPriv1Luid { public int Count; public long Luid; public int Attr; }
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002, TOKEN_QUERY = 0x00000008, TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static bool AddPrivilege(string privilege) {
        IntPtr hproc = GetCurrentProcess(), htok = IntPtr.Zero;
        TokPriv1Luid tp = new TokPriv1Luid { Count = 1, Luid = 0, Attr = SE_PRIVILEGE_ENABLED };
        if (OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok) && LookupPrivilegeValue(null, privilege, ref tp.Luid))
            return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return false;
    }
    public static bool RemovePrivilege(string privilege) {
        IntPtr hproc = GetCurrentProcess(), htok = IntPtr.Zero;
        TokPriv1Luid tp = new TokPriv1Luid { Count = 1, Luid = 0, Attr = 0 };
        if (OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok) && LookupPrivilegeValue(null, privilege, ref tp.Luid))
            return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        return false;
    }
    [DllImport("kernel32.dll")] public static extern IntPtr GetCurrentProcess();
}
"@ -Language CSharp
}
function Add-Privileges {'SeRestorePrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege','SeSystemEnvironmentPrivilege' | ForEach-Object { [Privileges]::AddPrivilege($_) | Out-Null }}
function Remove-Privileges {'SeRestorePrivilege','SeTakeOwnershipPrivilege','SeDebugPrivilege','SeSystemEnvironmentPrivilege' | ForEach-Object { [Privileges]::RemovePrivilege($_) | Out-Null }}

# Check system integrity
function HandleError {
    param([string]$Message)
    Write-Host "Error: $Message"
    pause
    $response = Read-Host "Do you want to run 'sfc /scannow' for system recovery? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Host "Starting system scan..."
        Start-Process -FilePath "cmd.exe" -ArgumentList "/c sfc /scannow & pause" -Verb RunAs
        Start-Sleep 2
        exit
    } else {
        Write-Host "Skipping system integrity check. If problems continue, consider reinstalling Windows." -ForegroundColor Red
        pause
        exit
    }
}

$ErrorActionPreference = 'SilentlyContinue'

try {
    if (!(Get-Command -Name Add-WindowsPackage -ErrorAction SilentlyContinue)) {
        $modulesPath = "C:\Windows\System32\WindowsPowerShell\v1.0\Modules"
        if (!(Test-Path $modulesPath)) {
            HandleError "Looks like the PowerShell modules directory is missing at '$modulesPath'."
        } else {
            HandleError "'Add-WindowsPackage' command is not available. This might mean Windows is corrupted."
        }
    }

    $registryPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\SideBySide'
    )
    foreach ($path in $registryPaths) {
        if (!(Test-Path $path)) {
            HandleError "Can't find the registry key at '$path'."
        }
    }

    $services = @('TrustedInstaller', 'wuauserv', 'bits', 'cryptsvc')
    foreach ($serviceName in $services) {
        $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
        if ($service -eq $null) {
            HandleError "'$serviceName' service is missing."
        }
    }
} catch {
    HandleError $_.Exception.Message
}

$ErrorActionPreference = 'Continue'

# Prerequisite
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class ConsoleManager
{
    [DllImport("kernel32.dll", ExactSpelling = true)]
    public static extern IntPtr GetConsoleWindow();

    [DllImport("user32.dll", CharSet = CharSet.Auto, SetLastError = true)]
    public static extern bool MoveWindow(IntPtr hWnd, int X, int Y, int nWidth, int nHeight, bool bRepaint);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetCurrentConsoleFontEx(IntPtr hConsoleOutput, bool bMaximumWindow, ref CONSOLE_FONT_INFO_EX lpConsoleCurrentFontEx);

    [DllImport("user32.dll")]
    public static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct CONSOLE_FONT_INFO_EX
    {
        public uint cbSize;
        public uint nFont;
        public COORD dwFontSize;
        public int FontFamily;
        public int FontWeight;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string FaceName;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct COORD
    {
        public short X;
        public short Y;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    public const int STD_OUTPUT_HANDLE = -11;

    public static void ResizeWindow(int width, int height)
    {
        IntPtr consoleHandle = GetConsoleWindow();
        MoveWindow(consoleHandle, 0, 0, width, height, true);
    }

    public static void SetConsoleFont(string fontName, short fontSize)
    {
        IntPtr hnd = GetStdHandle(STD_OUTPUT_HANDLE);
        CONSOLE_FONT_INFO_EX info = new CONSOLE_FONT_INFO_EX();
        info.cbSize = (uint)Marshal.SizeOf(info);
        info.FaceName = fontName;
        info.dwFontSize = new COORD { X = fontSize, Y = fontSize };
        info.FontFamily = 54;  // FF_DONTCARE | DEFAULT_PITCH
        info.FontWeight = 400; // Normal
        SetCurrentConsoleFontEx(hnd, false, ref info);
    }

    public static void QuickEditOFF()
    {
        IntPtr hConIn = GetStdHandle(-10);
        uint dwOldMode;
        if (GetConsoleMode(hConIn, out dwOldMode))
        {
            SetConsoleMode(hConIn, (uint)((dwOldMode | 0x80) & ~0x40));
        }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetConsoleMode(IntPtr hConsoleHandle, out uint lpMode);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool SetConsoleMode(IntPtr hConsoleHandle, uint dwMode);
}
"@

function AdjustDesign {
    param ([switch]$QuickEdit)
    Add-Type -AssemblyName System.Windows.Forms

    $host.PrivateData.WarningBackgroundColor = 'Black'
    $host.PrivateData.ErrorBackgroundColor = 'Black'
    $host.PrivateData.VerboseBackgroundColor = 'Black'
    $host.PrivateData.DebugBackgroundColor = 'Black'
    $host.UI.RawUI.BackgroundColor = [System.ConsoleColor]::Black
    $host.UI.RawUI.ForegroundColor = [System.ConsoleColor]::White

    if ($QuickEdit) {[ConsoleManager]::QuickEditOFF()}
    [ConsoleManager]::ResizeWindow(850, 550)
    [ConsoleManager]::SetConsoleFont("Consolas", 16)

    $hwnd = [ConsoleManager]::GetConsoleWindow()
    $rect = New-Object ConsoleManager+RECT
    [ConsoleManager]::GetWindowRect($hwnd, [ref]$rect) | Out-Null

    $screen = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
    $windowWidth = $rect.Right - $rect.Left
    $windowHeight = $rect.Bottom - $rect.Top
    $screenWidth = $screen.Width
    $screenHeight = $screen.Height
    $newX = [Math]::Max(0, [Math]::Round(($screenWidth - $windowWidth) / 2))
    $newY = [Math]::Max(0, [Math]::Round(($screenHeight - $windowHeight) / 2))
    [ConsoleManager]::MoveWindow($hwnd, $newX, $newY, $windowWidth, $windowHeight, $true) | Out-Null
}

function CheckDefenderStatus {
    $packageResult = (Get-WindowsPackage -online | Where-Object { $_.PackageName -like '*AntiBlocker*' })
    $serviceResult = (Get-Service -Name WinDefend -ErrorAction SilentlyContinue | Select-Object -ExpandProperty StartType)
    $serviceResult = $serviceResult -replace "`r`n", ""

    if ($packageResult -or $serviceResult -eq 'Disabled') {
        $global:status = "disabled"
    } else {
        $global:status = "enabled"
    }
}

$pingResult = & ping -n 2 google.com | Select-String "TTL="
$existingFile = if (Test-Path "$env:WinDir\DefenderSwitcher") { Get-ChildItem -Path "$env:WinDir\DefenderSwitcher" -Filter "*AntiBlocker*" -File | Select-Object -First 1 } else { $null }
$programUsable = $false

switch ($existingFile) {
    $null {
        if (!$pingResult) {
            $programUsable = $false
        } else {
            $destinationDir = "$env:WinDir\DefenderSwitcher"
            $fileName = "Z-RapidOS-AntiBlocker-Package31bf3856ad364e35amd645.0.0.0.cab"
            $destinationPath = Join-Path -Path $destinationDir -ChildPath $fileName
            $fileUrl = "https://rapid-community.ru/downloads/$fileName"

            if (!(Test-Path -Path $destinationDir)) {
                New-Item -Path $destinationDir -ItemType Directory | Out-Null
            }

            curl.exe -s -o $destinationPath $fileUrl > $null 2>&1
            $programUsable = $true
        }
        break
    } 
    default {
        $programUsable = $true
        $destinationDir = "$env:WinDir\DefenderSwitcher"
        $fileName = "Z-RapidOS-AntiBlocker-Package31bf3856ad364e35amd645.0.0.0.cab"
        $destinationPath = Join-Path -Path $destinationDir -ChildPath $fileName
        $fileUrl = "https://rapid-community.ru/downloads/$fileName"

        $tempFile = Join-Path -Path $env:TEMP -ChildPath $fileName
        curl.exe -s -o $tempFile $fileUrl > $null 2>&1

        if ((Test-Path -Path $tempFile) -and (Test-Path -Path $destinationPath)) {
            if ((Get-FileHash -Path $tempFile).Hash -ne (Get-FileHash -Path $destinationPath).Hash) {
                Move-Item -Path $tempFile -Destination $destinationPath -Force
            } else {
                Remove-Item -Path $tempFile
            }
        }
        break
    }
}

function MainMenu {
    cls
    CheckDefenderStatus;
    Write-Host "`n`n`n`n"
    Write-Host "         ______________________________________________________________" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "                               Defender Switcher"
    Write-Host ""
    Write-Host "                                Current Status:" -ForegroundColor Yellow
    if ($status -eq "enabled")
    { Write-Host "                          Windows Defender is ENABLED" -ForegroundColor Green }
else{ Write-Host "                          Windows Defender's DISABLED" -ForegroundColor Red }
    if ($programUsable -eq $true) 
    { Write-Host "                            Defender can be toggled" -ForegroundColor Green }
else{ Write-Host "                            Connect to the Internet" -ForegroundColor Red }
    Write-Host "               __________________________________________________" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "                               Choose an option:" -ForegroundColor Yellow

    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "               ["; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host -NoNewline "1"; $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Enable Windows Defender  | Restore Protection"
    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "               ["; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host -NoNewline "2"; $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Disable Windows Defender | Turn Off Protection"
    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "               ["; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host -NoNewline "3"; $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Information              | Useful Information"
    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "               ["; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host -NoNewline "4"; $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Exit                     | Close Program"

    Write-Host ""
    Write-Host "               __________________________________________________" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "              Choose a menu option using your keyboard [1,2,3,4] :" -ForegroundColor Green
    Write-Host ""
    Write-Host "         ______________________________________________________________" -ForegroundColor DarkGray
    Write-Host ""

    $host.UI.RawUI.KeyAvailable > $null 2>&1
    $choice = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').Character

    switch ($choice) {
        '1' { EnableDefender }
        '2' { DisableDefender }
        '3' { ShowInformation }
        '4' { ExitProgram }
        default { MainMenu }
    }
}

function EnableDefender {
    cls
    CheckDefenderStatus;
    switch ($status) {
        "enabled" {
            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Defender is already enabled."
        }
        default {
            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "PROCESSING"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Enabling Defender..."
            
            Add-Privileges
            $ProgressPreference = 'SilentlyContinue'; $WarningPreference = 'SilentlyContinue'; 
            Get-WindowsPackage -Online | Where-Object { $_.PackageName -like '*AntiBlocker*' } | ForEach-Object {
                Remove-WindowsPackage -Online -PackageName $_.PackageName -NoRestart
            } | Out-Null 2>&1
            $ProgressPreference = 'Continue'; $WarningPreference = 'Continue'; 
            Remove-Privileges

            CheckDefenderStatus;
            switch ($status) {
                "enabled" {
                    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Defender has been enabled."
                }
                default {
                    $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Failed to enable Defender."
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
    if (!$interactiveMode) {

    }
    switch ($status) {
        "disabled" {
            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Defender is already disabled."
        }
        default {
            if ($programUsable -eq $true) {
                $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "PROCESSING"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Disabling Defender..."
                Add-Privileges 
                ProcessDefender -InstallCAB $true
                ProcessDefender -LinkManifests $true
                Remove-Privileges
                CheckDefenderStatus;
                switch ($status) {
                    "disabled" {
                        $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Defender has been disabled."
                    }
                    default {
                        $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Failed to enable Defender."
                        Write-Host ""
                        Write-Host "Try to reboot your PC and try again."
                        Write-Host "If error occurs, try to use program in safe boot with ethernet option."
                        Write-Host "If nothing helped, please, make an issue on GitHub or write in Rapid Community's discord server for help."
                    }
                }
            } else {
                $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Connect to the internet and restart Defender Switcher to proceed." 
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
    param (
        [switch]$InstallCAB,
        [switch]$LinkManifests
    )
 
    if ($InstallCAB) {
        $cabPath = Get-ChildItem -Path "$env:WinDir\DefenderSwitcher" -Filter "*AntiBlocker*" -File | Select-Object -First 1

        if (!$cabPath) {
            $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Connect to the internet and restart Defender Switcher to proceed." 
            return
        }

        $filePath = $cabPath.FullName
    
        $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Checking certificate..."
        try {       
            $cert = (Get-AuthenticodeSignature $filePath).SignerCertificate
            if ($cert.Extensions.EnhancedKeyUsages.Value -ne "1.3.6.1.4.1.311.10.3.6") {
                $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Cert doesn't have proper key usages, can't continue."
                return
            }

            $certRegPath = "HKLM:\Software\Microsoft\SystemCertificates\ROOT\Certificates\8A334AA8052DD244A647306A76B8178FA215F344"
            if (!(Test-Path "$certRegPath")) {
                New-Item -Path $certRegPath -Force | Out-Null
            }
        } catch {
            $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Cert error from '$filePath': $_"
            return
        }
    
        $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Adding package..."
        try {
            $ProgressPreference = 'SilentlyContinue'
            Add-WindowsPackage -Online -PackagePath $filePath -NoRestart -IgnoreCheck -LogLevel 1 *>$null
            $ProgressPreference = 'Continue'
        } catch {
            $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Error when adding package '$filePath': $_"
            return
        }
    }

    if ($LinkManifests) { 
        CheckDefenderStatus;
        if ($status -eq "disabled") {
            $version = '38655.38527.65535.65535'
        	$srcPathExpanded = [System.Environment]::ExpandEnvironmentVariables("%WinDir%\DefenderSwitcher\WinSxS")

            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Getting manifests..."
        	$manifests = Get-ChildItem "$env:WinDir\WinSxS\Manifests" -File -Filter "*$version*"
        	if ($manifests.Count -eq 0) {
                $host.UI.RawUI.ForegroundColor = 'Red'; Write-Host -NoNewline "["; Write-Host -NoNewline "ERROR"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "No manifests found! Can't create repair source."
	        	return
	        }

	        if (Test-Path $srcPathExpanded -PathType Container) {
                $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Deleting old RepairSrc..."
	        	Remove-Item $srcPathExpanded -Force -Recurse
	        }
            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Creating RepairSrc path..."
	        New-Item "$srcPathExpanded\Manifests" -Force -ItemType Directory | Out-Null

            $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "["; Write-Host -NoNewline "INFO"; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Hard linking manifests..."
            foreach ($manifest in $manifests) {
	        	New-Item -ItemType HardLink -Path "$srcPathExpanded\Manifests\$manifest" -Target $manifest.FullName | Out-Null
	        }

	        $servicingPolicyKey = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Servicing"
	        if (!(Test-Path $servicingPolicyKey)) { New-Item -Path $servicingPolicyKey -Force | Out-Null }
	        Set-ItemProperty -Path $servicingPolicyKey -Name LocalSourcePath -Value "%WinDir%\DefenderSwitcher\WinSxS" -Type ExpandString -Force
        }
    }
}

function ShowInformation {
    cls
    Write-Host "`n`n`n`n"
    Write-Host "         ______________________________________________________________" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "                               Defender Switcher"
    Write-Host ""
    Write-Host "               Credits:" -ForegroundColor Yellow
    Write-Host ""
    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "               ["; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host -NoNewline "1"; $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "AtlasOS CAB Method"
    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "               ["; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host -NoNewline "2"; $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Design Based on MAS"
    Write-Host ""
    Write-Host "               __________________________________________________" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "               Our links:" -ForegroundColor Yellow
    Write-Host ""
    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "               ["; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host -NoNewline "3"; $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "GitHub"
    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "               ["; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host -NoNewline "4"; $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Discord"
    $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "               ["; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host -NoNewline "5"; $host.UI.RawUI.ForegroundColor = 'Green'; Write-Host -NoNewline "] "; $host.UI.RawUI.ForegroundColor = 'White'; Write-Host "Website"                     
    Write-Host ""
    Write-Host "               __________________________________________________" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host "            Choose a menu option using your keyboard [1,2,3,4,5,q] :" -ForegroundColor Green
    Write-Host ""
    Write-Host "         ______________________________________________________________" -ForegroundColor DarkGray
    $choice = ""
    while ($choice -ne 'q') {
        $choice = $host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown').Character
        switch ($choice) {
            '1' { Start-Process "https://github.com/Atlas-OS/Atlas" }
            '2' { Start-Process "https://github.com/massgravel/Microsoft-Activation-Scripts" }
            '3' { Start-Process "https://github.com/instead1337/Defender-Switcher" }
            '4' { Start-Process "https://dsc.gg/rapid-community" }
            '5' { Start-Process "https://rapid-community.ru" }
            'q' { MainMenu }
        }
    }
}

function ExitProgram {
    Write-Host "         3..."
    Start-Sleep -Seconds 1
    Write-Host "         2..."
    Start-Sleep -Seconds 1
    Write-Host "         1..."
    Start-Sleep -Seconds 1
    exit
}

if ($enable_av) { AdjustDesign; EnableDefender }
if ($disable_av) { AdjustDesign; DisableDefender }
if ($interactiveMode) { AdjustDesign -QuickEdit; MainMenu } else { exit } 