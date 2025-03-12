# Windows PowerShell AdminToolkit

[English](#english) | [Türkçe](#turkish)

<a name="english"></a>
## English

### Description
Windows PowerShell AdminToolkit is a comprehensive collection of PowerShell scripts designed to assist system administrators in managing Windows environments. The toolkit includes scripts for system management, file operations, network operations, security, automation, database management, reporting, and web operations.

### Directory Structure
```
Windows-PowerShell-AdminToolkit/
├── SystemManagement/
│   ├── Get-SystemInfo.ps1
│   ├── Check-DiskSpace.ps1
│   ├── Monitor-Services.ps1
│   └── Manage-WindowsUpdates.ps1
├── FileOperations/
│   ├── Backup-Files.ps1
│   ├── Rename-BulkFiles.ps1
│   ├── Organize-FilesByExtension.ps1
│   └── Archive-Files.ps1
├── NetworkOperations/
│   ├── Test-NetworkConnection.ps1
│   ├── Scan-Ports.ps1
│   ├── Manage-IPAddresses.ps1
│   └── Manage-RemoteComputers.ps1
├── Security/
│   ├── Security-Audit.ps1
│   ├── Analyze-Logs.ps1
│   ├── Manage-UserAccounts.ps1
│   └── Run-AntivirusScan.ps1
├── Automation/
│   ├── Schedule-Tasks.ps1
│   ├── Manage-Applications.ps1
│   ├── Backup-Data.ps1
│   └── Send-Email.ps1
├── Database/
│   ├── Backup-Database.ps1
│   ├── Transfer-Data.ps1
│   └── Execute-Queries.ps1
├── Reporting/
│   ├── Generate-SystemReport.ps1
│   ├── Monitor-Performance.ps1
│   └── Generate-ErrorReport.ps1
├── WebOperations/
│   ├── Test-WebServices.ps1
│   ├── Invoke-APIRequests.ps1
│   └── Download-WebContent.ps1
├── README.md
└── LICENSE
```

### Installation
1. Clone the repository:
   ```powershell
   git clone https://github.com/faust-lvii/Windows-PowerShell-AdminToolkit.git
   ```

2. Navigate to the directory:
   ```powershell
   cd Windows-PowerShell-AdminToolkit
   ```

3. Ensure script execution is allowed on your system:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Usage
Each script can be run individually from PowerShell. Most scripts include help documentation that can be accessed using the Get-Help cmdlet:

```powershell
Get-Help .\SystemManagement\Get-SystemInfo.ps1 -Full
```

Example usage:
```powershell
# Get system information
.\SystemManagement\Get-SystemInfo.ps1

# Check disk space with warning threshold
.\SystemManagement\Check-DiskSpace.ps1 -WarningThreshold 10

# Backup files
.\FileOperations\Backup-Files.ps1 -SourcePath "C:\Data" -DestinationPath "D:\Backup"
```

### Requirements
- Windows PowerShell 5.1 or PowerShell Core 7.x
- Windows 10/11 or Windows Server 2016/2019/2022
- Administrator privileges for certain scripts
- Internet connection for scripts that download content or check for updates

### Contributing
Contributions to the Windows PowerShell AdminToolkit are welcome! Here's how you can contribute:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature-name`)
3. Commit your changes (`git commit -m 'Add some feature'`)
4. Push to the branch (`git push origin feature/your-feature-name`)
5. Open a Pull Request

Please ensure your code follows these guidelines:
- Use descriptive variable names
- Include proper error handling
- Add comments to explain complex sections
- Write help documentation for each script
- Follow PowerShell best practices

---

<a name="turkish"></a>
## Türkçe

### Açıklama
Windows PowerShell AdminToolkit, Windows ortamlarını yönetmekte sistem yöneticilerine yardımcı olmak için tasarlanmış kapsamlı bir PowerShell betik koleksiyonudur. Toolkit, sistem yönetimi, dosya işlemleri, ağ işlemleri, güvenlik, otomasyon, veritabanı yönetimi, raporlama ve web işlemleri için betikler içerir.

### Dizin Yapısı
```
Windows-PowerShell-AdminToolkit/
├── SystemManagement/
│   ├── Get-SystemInfo.ps1
│   ├── Check-DiskSpace.ps1
│   ├── Monitor-Services.ps1
│   └── Manage-WindowsUpdates.ps1
├── FileOperations/
│   ├── Backup-Files.ps1
│   ├── Rename-BulkFiles.ps1
│   ├── Organize-FilesByExtension.ps1
│   └── Archive-Files.ps1
├── NetworkOperations/
│   ├── Test-NetworkConnection.ps1
│   ├── Scan-Ports.ps1
│   ├── Manage-IPAddresses.ps1
│   └── Manage-RemoteComputers.ps1
├── Security/
│   ├── Security-Audit.ps1
│   ├── Analyze-Logs.ps1
│   ├── Manage-UserAccounts.ps1
│   └── Run-AntivirusScan.ps1
├── Automation/
│   ├── Schedule-Tasks.ps1
│   ├── Manage-Applications.ps1
│   ├── Backup-Data.ps1
│   └── Send-Email.ps1
├── Database/
│   ├── Backup-Database.ps1
│   ├── Transfer-Data.ps1
│   └── Execute-Queries.ps1
├── Reporting/
│   ├── Generate-SystemReport.ps1
│   ├── Monitor-Performance.ps1
│   └── Generate-ErrorReport.ps1
├── WebOperations/
│   ├── Test-WebServices.ps1
│   ├── Invoke-APIRequests.ps1
│   └── Download-WebContent.ps1
├── README.md
└── LICENSE
```

### Kurulum
1. Repo'yu klonlayın:
   ```powershell
   git clone https://github.com/faust-lvii/Windows-PowerShell-AdminToolkit.git
   ```

2. Dizine gidin:
   ```powershell
   cd Windows-PowerShell-AdminToolkit
   ```

3. Betik çalıştırma izninin etkin olduğundan emin olun:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   ```

### Kullanım
Her betik PowerShell'den ayrı ayrı çalıştırılabilir. Çoğu betik, Get-Help cmdlet'i kullanılarak erişilebilen yardım belgeleri içerir:

```powershell
Get-Help .\SystemManagement\Get-SystemInfo.ps1 -Full
```

Örnek kullanım:
```powershell
# Sistem bilgilerini almak
.\SystemManagement\Get-SystemInfo.ps1

# Belirli bir uyarı eşiği ile disk alanını kontrol etmek
.\SystemManagement\Check-DiskSpace.ps1 -WarningThreshold 10

# Dosyaları yedeklemek
.\FileOperations\Backup-Files.ps1 -SourcePath "C:\Data" -DestinationPath "D:\Backup"
```

### Gereksinimler
- Windows PowerShell 5.1 veya PowerShell Core 7.x
- Windows 10/11 veya Windows Server 2016/2019/2022
- Bazı betikler için yönetici ayrıcalıkları
- İçerik indiren veya güncellemeleri kontrol eden betikler için internet bağlantısı

### Katkıda Bulunma
Windows PowerShell AdminToolkit'e katkılarınızı bekliyoruz! İşte katkıda bulunabileceğiniz yollar:

1. Repo'yu forklayın
2. Bir özellik dalı oluşturun (`git checkout -b ozellik/ozellik-adi`)
3. Değişikliklerinizi commit edin (`git commit -m 'Yeni özellik eklendi'`)
4. Dal'a push yapın (`git push origin ozellik/ozellik-adi`)
5. Bir Pull Request açın

Lütfen kodunuzun şu yönergeleri izlediğinden emin olun:
- Açıklayıcı değişken adları kullanın
- Uygun hata yakalama ekleyin
- Karmaşık bölümleri açıklamak için yorumlar ekleyin
- Her betik için yardım belgeleri yazın
- PowerShell en iyi uygulamalarını takip edin

