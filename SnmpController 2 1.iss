[Setup]
AppName=SNMP Controller
AppVersion=1.0.5
AppPublisher=CT Galega
AppPublisherURL=https://www.ctgalega.com/
DefaultDirName={pf}\SnmpController
DefaultGroupName=CT Galega
UninstallDisplayIcon={app}\main.exe
SetupIconFile=compiler:SetupClassicIcon.ico
Compression=lzma2/ultra
SolidCompression=yes
OutputDir=C:\Users\tferreira\Projetos\InstallerBuilder_py
OutputBaseFilename=SnmpController
PrivilegesRequired=admin
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
WizardStyle=modern
DisableWelcomePage=no
DisableDirPage=no
DisableProgramGroupPage=yes

[Languages]
Name: "spanish"; MessagesFile: "compiler:Languages\Spanish.isl"

[Files]
Source: "main.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "config.ini"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "nssm-2.24\win64\nssm.exe"; DestDir: "{app}"; Flags: ignoreversion

[Dirs]
Name: "{app}\logs"; Permissions: users-modify

[Run]
Filename: "{app}\nssm.exe"; Parameters: "install SNMPService ""{app}\main.exe"""; \
    StatusMsg: "Instalando serviço..."; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "set SNMPService DisplayName ""SNMP Controller"""; \
    StatusMsg: "Configurando nome do serviço..."; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "set SNMPService Description ""Serviço para monitoramento de dispositivos via SNMP"""; \
    StatusMsg: "Configurando descrição..."; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "set SNMPService AppDirectory ""{app}"""; \
    StatusMsg: "Configurando diretório..."; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "set SNMPService AppStdout ""{app}\logs\service.log"""; \
    StatusMsg: "Configurando logs..."; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "set SNMPService AppStderr ""{app}\logs\error.log"""; \
    StatusMsg: "Configurando logs de erro..."; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "set SNMPService AppThrottle 15000"; \
    StatusMsg: "Configurando proteção..."; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "set SNMPService AppExit Default Restart"; \
    StatusMsg: "Configurando recuperação..."; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "set SNMPService AppRestartDelay 60000"; \
    StatusMsg: "Configurando atraso..."; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "set SNMPService AppStopMethodSkip 6"; Flags: runhidden waituntilterminated
Filename: "{app}\nssm.exe"; Parameters: "set SNMPService AppStopMethodConsole 1000"; Flags: runhidden waituntilterminated

Filename: "{app}\nssm.exe"; Parameters: "start SNMPService"; \
    StatusMsg: "Iniciando serviço..."; Flags: runhidden waituntilterminated

[UninstallRun]
Filename: "{app}\nssm.exe"; Parameters: "remove SNMPService confirm"; Flags: runhidden waituntilterminated

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"

[Code]
var
  PaginaCliente: TInputQueryWizardPage;
  PaginaCredenciales: TInputQueryWizardPage;
  PaginaProgreso: TOutputProgressWizardPage;
  globalSID: string;
  DebeVolverAPaginaCliente: Boolean;

const
  URL_API_PREDETERMINADA = 'https://ctgtest02.spaincentral.cloudapp.azure.com';
  URL_API_LOGIN = URL_API_PREDETERMINADA + '/api/method/login';
  URL_API_CLIENTE = URL_API_PREDETERMINADA + '/api/resource/CI%20Cliente/';
  URL_API_UBICACION = URL_API_PREDETERMINADA + '/api/resource/CI%20Ubicacion/';
  
procedure Log(const Msg: string);
begin
  SaveStringToFile(ExpandConstant('{tmp}\installation.log'), GetDateTimeString('yyyy/mm/dd hh:nn:ss', '-', ':') + ' - ' + Msg + #13#10, True);
end;

function FindNSSM(): String;
var
  NSSMPath: String;
  SystemDir: String;
  ProgramFilesDir: String;
  ProgramFilesDir64: String;
begin
  Log('Procurando por nssm.exe...');
  
  // 1. Verifica na pasta do aplicativo (prioridade máxima)
  NSSMPath := ExpandConstant('{app}\nssm.exe');
  if FileExists(NSSMPath) then
  begin
    Log('Encontrado em: ' + NSSMPath);
    Result := NSSMPath;
    Exit;
  end;

  // 2. Verifica no diretório System32
  SystemDir := ExpandConstant('{sys}');
  NSSMPath := SystemDir + '\nssm.exe';
  if FileExists(NSSMPath) then
  begin
    Log('Encontrado em: ' + NSSMPath);
    Result := NSSMPath;
    Exit;
  end;

  // 3. Verifica no diretório Program Files (x86)
  ProgramFilesDir := ExpandConstant('{pf32}');
  NSSMPath := ProgramFilesDir + '\nssm\nssm.exe';
  if FileExists(NSSMPath) then
  begin
    Log('Encontrado em: ' + NSSMPath);
    Result := NSSMPath;
    Exit;
  end;

  // 4. Verifica no diretório Program Files (64-bit)
  ProgramFilesDir64 := ExpandConstant('{pf64}');
  NSSMPath := ProgramFilesDir64 + '\nssm\nssm.exe';
  if FileExists(NSSMPath) then
  begin
    Log('Encontrado em: ' + NSSMPath);
    Result := NSSMPath;
    Exit;
  end;

  // 5. Verifica em outros locais comuns
  NSSMPath := 'C:\Program Files\nssm\nssm.exe';
  if FileExists(NSSMPath) then
  begin
    Log('Encontrado em: ' + NSSMPath);
    Result := NSSMPath;
    Exit;
  end;

  NSSMPath := 'C:\Program Files (x86)\nssm\nssm.exe';
  if FileExists(NSSMPath) then
  begin
    Log('Encontrado em: ' + NSSMPath);
    Result := NSSMPath;
    Exit;
  end;

  // Se não encontrou em nenhum lugar
  Log('nssm.exe não encontrado em nenhum local padrão');
  Result := '';
end;

procedure ConfigurarRecuperacaoServico;
var
  NSSM: String;
  ResultCode: Integer;
begin
  NSSM := FindNSSM();
  if NSSM = '' then exit;

  // Configura a política de recuperação para reiniciar após 1 e 2 falhas
  Exec(NSSM, 'set SNMPService AppExit Default Restart', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(NSSM, 'set SNMPService AppRestartDelay 60000', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(NSSM, 'set SNMPService AppThrottle 15000', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;
procedure VerifyServiceInstall;
var
  ResultCode: Integer;
  Output: AnsiString;
begin
  Log('Verifying service installation');
  
  if Exec('cmd.exe', '/C sc query SNMPService > "' + ExpandConstant('{tmp}\service_check.txt') + '"', 
     '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if LoadStringFromFile(ExpandConstant('{tmp}\service_check.txt'), Output) then
    begin
      Log('Service check output: ' + Output);
      
      if ResultCode <> 0 then
      begin
        Log('Service installation verification failed');
        MsgBox('Falha na verificação da instalação do serviço:' + #13#10 + Output, mbError, MB_OK);
      end
      else
      begin
        Log('Service installation verified successfully');
      end;
    end
    else
    begin
      Log('Could not read service check output');
      MsgBox('Não foi possível verificar a instalação do serviço.', mbError, MB_OK);
    end;
  end
  else
  begin
    Log('Failed to execute service check command');
    MsgBox('Falha ao verificar a instalação do serviço.', mbError, MB_OK);
  end;
end;  
procedure InstalarServicoViaNSSM;
var
  NSSM, AppPath: String;
  ResultCode: Integer;
begin
  NSSM := FindNSSM();
  if NSSM = '' then begin
    MsgBox('NSSM não foi encontrado.', mbError, MB_OK);
    exit;
  end;

  AppPath := ExpandConstant('{app}\main.exe');
  
  // Instala o serviço
  if not Exec(NSSM, 'install SNMPService "' + AppPath + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    Log('Erro ao instalar serviço: ' + IntToStr(ResultCode))
  else
    Log('Serviço instalado com sucesso.');

  // Configurações básicas
  Exec(NSSM, 'set SNMPService DisplayName "SNMP Controller"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(NSSM, 'set SNMPService Description "Serviço para monitoramento de dispositivos via SNMP"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(NSSM, 'set SNMPService AppDirectory "' + ExpandConstant('{app}') + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(NSSM, 'set SNMPService AppStdout "' + ExpandConstant('{app}\logs\service.log') + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Exec(NSSM, 'set SNMPService AppStderr "' + ExpandConstant('{app}\logs\error.log') + '"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  // Configura recuperação automática
  ConfigurarRecuperacaoServico;

  // Inicia o serviço
  Exec(NSSM, 'start SNMPService', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  
  // Verifica a instalação
  VerifyServiceInstall;
end;



function VerificarClienteExiste(CodigoCliente, APIUrl: string): Boolean;
var
  PeticionHTTP: Variant;
  URL_Cliente: string;
begin
  Result := False;
  
  try
    // Constrói a URL do cliente dinamicamente
    URL_Cliente := APIUrl;
    if not (Copy(APIUrl, Length(APIUrl), 1) = '/') then
      URL_Cliente := URL_Cliente + '/';
    URL_Cliente := URL_Cliente + 'api/resource/CI%20Cliente/' + CodigoCliente;
    
    Log('Verificando cliente na URL: ' + URL_Cliente);
    
    PeticionHTTP := CreateOleObject('WinHttp.WinHttpRequest.5.1');
    PeticionHTTP.Open('GET', URL_Cliente, False);
    PeticionHTTP.SetRequestHeader('Content-Type', 'application/json');
    
    if globalSID <> '' then
      PeticionHTTP.SetRequestHeader('Cookie', 'sid=' + globalSID);
    
    PeticionHTTP.Send('');
    
    Log('Resposta da verificação de cliente - Status: ' + IntToStr(PeticionHTTP.Status));
    
    if PeticionHTTP.Status = 200 then
    begin
      Result := True;
      Log('Cliente encontrado com sucesso');
    end
    else if PeticionHTTP.Status = 404 then
    begin
      Log('Cliente não encontrado (404)');
      MsgBox('Código de cliente não encontrado na API.', mbError, MB_OK);
    end
    else
    begin
      Log('Erro na verificação do cliente - Status: ' + IntToStr(PeticionHTTP.Status));
      MsgBox('Erro ao verificar cliente. Código: ' + IntToStr(PeticionHTTP.Status), mbError, MB_OK);
    end;
  except
    Log('Exceção durante verificação de cliente: ' + GetExceptionMessage);
    MsgBox('Erro ao conectar com a API para verificar cliente.', mbError, MB_OK);
  end;
end;

function VerificarUbicacionExiste(Ubicacion: string): Boolean;
var
  PeticionHTTP: Variant;
begin
  if Trim(Ubicacion) = '' then
  begin
    Log('Empty location - skipping verification');
    Result := True;
    Exit;
  end;

  Result := False;
  Log('Verifying location existence: ' + Ubicacion);
  
  try
    PeticionHTTP := CreateOleObject('WinHttp.WinHttpRequest.5.1');
    PeticionHTTP.Open('GET', URL_API_UBICACION + Ubicacion, False);
    PeticionHTTP.SetRequestHeader('Content-Type', 'application/json');
    
    if globalSID <> '' then
      PeticionHTTP.SetRequestHeader('Cookie', 'sid=' + globalSID);
    
    PeticionHTTP.Send('');
    
    Log('Location verification response: ' + IntToStr(PeticionHTTP.Status));
    
    if PeticionHTTP.Status = 200 then
    begin
      Result := True;
      Log('Location verification successful');
    end
    else if PeticionHTTP.Status = 404 then
    begin
      Log('Location not found in API');
      MsgBox('Ubicación no encontrada en la API. Verifique el valor e intente nuevamente.', mbError, MB_OK);
    end
    else
    begin
      Log('Error verifying location. Status: ' + IntToStr(PeticionHTTP.Status));
      MsgBox('Error al verificar ubicación. Código: ' + IntToStr(PeticionHTTP.Status), mbError, MB_OK);
    end;
  except
    Log('Exception verifying location: ' + GetExceptionMessage);
    MsgBox('Error al conectar con la API para verificar ubicación.', mbError, MB_OK);
  end;
end;

function DividirCadena(const Cadena, Delimitador: string): TArrayOfString;
var
  i, p: Integer;
  S: string;
begin
  S := Cadena;
  i := 0;
  SetArrayLength(Result, 0);
  
  while Length(S) > 0 do
  begin
    p := Pos(Delimitador, S);
    if p > 0 then
    begin
      SetArrayLength(Result, i+1);
      Result[i] := Copy(S, 1, p-1);
      S := Copy(S, p + Length(Delimitador), MaxInt);
      Inc(i);
    end
    else
    begin
      SetArrayLength(Result, i+1);
      Result[i] := S;
      Break;
    end;
  end;
end;

function VerificarCredencialesYObternerSID(const APIUrl, Usuario, Contrasena: string; var SID: string): Boolean;
var
  PeticionHTTP: Variant;
  CabeceraCookie: string;
  PartesCookie: TArrayOfString;
  i: Integer;
  URL_Login: string;
begin
  Result := False;
  SID := '';
  
  try
    // Constrói a URL de login dinamicamente
    URL_Login := APIUrl;
    if not (Copy(APIUrl, Length(APIUrl), 1) = '/') then
      URL_Login := URL_Login + '/';
    URL_Login := URL_Login + 'api/method/login';
    
    Log('Tentando login na URL: ' + URL_Login);
    
    PeticionHTTP := CreateOleObject('WinHttp.WinHttpRequest.5.1');
    PeticionHTTP.Open('POST', URL_Login, False);
    PeticionHTTP.SetRequestHeader('Content-Type', 'application/json');
    PeticionHTTP.Send('{"usr":"' + Usuario + '","pwd":"' + Contrasena + '"}');
    
    Log('Resposta do login - Status: ' + IntToStr(PeticionHTTP.Status));
    
    if PeticionHTTP.Status = 200 then
    begin
      CabeceraCookie := PeticionHTTP.GetResponseHeader('Set-Cookie');
      if CabeceraCookie <> '' then
      begin
        Log('Cookies recebidos: ' + CabeceraCookie);
        PartesCookie := DividirCadena(CabeceraCookie, ';');
        
        for i := 0 to GetArrayLength(PartesCookie)-1 do
        begin
          if Pos('sid=', Trim(PartesCookie[i])) = 1 then
          begin
            SID := Copy(Trim(PartesCookie[i]), Pos('=', Trim(PartesCookie[i])) + 1, MaxInt);
            Log('SID encontrado: ' + SID);
            Result := True;
            Break;
          end;
        end;
      end;
    end
    else
    begin
      Log('Falha no login - Status: ' + IntToStr(PeticionHTTP.Status) + ' - Resposta: ' + PeticionHTTP.ResponseText);
    end;
  except
    Log('Exceção durante verificação de credenciais: ' + GetExceptionMessage);
    MsgBox('Erro ao conectar com o servidor. Verifique a URL e tente novamente.', mbError, MB_OK);
  end;
end;

function EncriptarContrasena(const Entrada: string): string;
var
  i: Integer;
  Clave: string;
  Encriptado: string;
  ValorCaracter: Integer;
begin
  Clave := 'CTGalegaEncKey2023!';
  Encriptado := '';
  for i := 1 to Length(Entrada) do
  begin
    ValorCaracter := Ord(Entrada[i]) xor Ord(Clave[(i-1) mod Length(Clave) + 1]);
    Encriptado := Encriptado + Format('%.2x', [ValorCaracter]);
  end;
  Result := Encriptado;
end;

procedure InitializeWizard;
begin
  WizardForm.Caption := 'Instalador de SNMP Controller';
  
  PaginaCliente := CreateInputQueryPage(wpWelcome,
    'Configuração do Cliente',
    'Informação do Cliente',
    'Por favor, introduzca el código de cliente y ubicación:');
  PaginaCliente.Add('Código de Cliente:', False);
  PaginaCliente.Add('Filtro de Ubicación (opcional):', False);
  
  PaginaCredenciales := CreateInputQueryPage(PaginaCliente.ID,
    'Credenciales de Acceso',
    'Autenticación del Servicio',
    'Por favor, introduzca sus credenciales:');
  PaginaCredenciales.Add('URL da API:', False);
  PaginaCredenciales.Values[0] := URL_API_PREDETERMINADA;
  PaginaCredenciales.Add('Usuario:', False);
  PaginaCredenciales.Add('Contraseña:', True);

  PaginaProgreso := CreateOutputProgressPage('Validando', 'Por favor espere...');
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  Usuario, Contrasena, SID, APIUrl: string;
begin
  Result := True;
  
  if CurPageID = PaginaCliente.ID then
  begin
    if Trim(PaginaCliente.Values[0]) = '' then
    begin
      MsgBox('El código de cliente es obligatorio.', mbError, MB_OK);
      Result := False;
    end;
  end
  else if CurPageID = PaginaCredenciales.ID then
  begin
    APIUrl := Trim(PaginaCredenciales.Values[0]);
    Usuario := Trim(PaginaCredenciales.Values[1]);
    Contrasena := Trim(PaginaCredenciales.Values[2]);
    
    if APIUrl = '' then
    begin
      MsgBox('A URL da API é obrigatória.', mbError, MB_OK);
      Result := False;
    end
    else if (Usuario = '') or (Contrasena = '') then
    begin
      MsgBox('Usuario y contraseña son obligatorios.', mbError, MB_OK);
      Result := False;
    end
    else
    begin
      PaginaProgreso.SetText('Verificando...', 'Por favor espere...');
      PaginaProgreso.Show;
      try
        if not VerificarCredencialesYObternerSID(APIUrl, Usuario, Contrasena, SID) then
        begin
          MsgBox('Credenciales inválidas', mbError, MB_OK);
          Result := False;
        end
        else
        begin
          globalSID := SID;
          if not VerificarClienteExiste(PaginaCliente.Values[0], APIUrl) then
          begin
            MsgBox('Cliente no encontrado', mbError, MB_OK);
            Result := False;
          end;
        end;
      finally
        PaginaProgreso.Hide;
      end;
    end;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  Log('Page changed to: ' + IntToStr(CurPageID));
  if (CurPageID = PaginaCredenciales.ID) and DebeVolverAPaginaCliente then
  begin
    DebeVolverAPaginaCliente := False;
    WizardForm.BackButton.OnClick(nil);
  end;
end;

procedure EstablecerPermisosConfig;
var
  CodigoResultado: Integer;
begin
  Log('Setting config file permissions');
  Exec(ExpandConstant('{sys}\icacls.exe'),
    '"' + ExpandConstant('{app}\config.ini') + '" /inheritance:r /grant:r *S-1-5-32-544:F /grant:r *S-1-5-18:F /grant:r "' + ExpandConstant('{userinfoname}') + '":F',
    '', SW_HIDE, ewWaitUntilTerminated, CodigoResultado);
  Log('Config file permissions set with exit code: ' + IntToStr(CodigoResultado));
  Exec(ExpandConstant('{sys}\icacls.exe'),
    '"' + ExpandConstant('{app}\logs') + '" /inheritance:r /grant:r *S-1-5-32-544:F /grant:r *S-1-5-18:F /grant:r "' + ExpandConstant('{userinfoname}') + '":F',
    '', SW_HIDE, ewWaitUntilTerminated, CodigoResultado);
  Log('Logs directory permissions set with exit code: ' + IntToStr(CodigoResultado));
end;

procedure VerifyInstallationFiles();
var
  RequiredFiles: array of String;
  i: Integer;
begin
  Log('Verifying installation files');
  RequiredFiles := [
    ExpandConstant('{app}\main.exe'),
    ExpandConstant('{app}\config.ini'),
    ExpandConstant('{app}\nssm.exe')
  ];
  
  for i := 0 to GetArrayLength(RequiredFiles) - 1 do
  begin
    if not FileExists(RequiredFiles[i]) then
    begin
      Log('ERROR: File not found: ' + RequiredFiles[i]);
      RaiseException('Archivo esencial no encontrado: ' + ExtractFileName(RequiredFiles[i]));
    end
    else
    begin
      Log('File verified: ' + RequiredFiles[i]);
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfigFile, LogDir, EncPass, APIUrl: String;
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    try
      VerifyInstallationFiles();
      
      APIUrl := Trim(PaginaCredenciales.Values[0]); 
      LogDir := ExpandConstant('{app}\logs');
      if not DirExists(LogDir) then 
        if not ForceDirectories(LogDir) then
          RaiseException('Falha ao criar diretório de logs');
      
      ConfigFile := ExpandConstant('{app}\config.ini');
      EncPass := EncriptarContrasena(PaginaCredenciales.Values[2]);
      
      SaveStringToFile(ConfigFile,
        '[DEFAULT]' + #13#10 +
        'service_url = ' + APIUrl + #13#10 + 
        'username = ' + PaginaCredenciales.Values[1] + #13#10 +
        'password_enc = ' + EncPass + #13#10 +
        'client_code = ' + PaginaCliente.Values[0] + #13#10 +
        'location_filter = ' + PaginaCliente.Values[1] + #13#10 +
        'log_path = ' + LogDir + #13#10, False);

      EstablecerPermisosConfig;
      InstalarServicoViaNSSM;
    except
      MsgBox('Error: ' + GetExceptionMessage, mbError, MB_OK);
      Abort;
    end;
  end;
end;

function InitializeSetup(): Boolean;
begin
  Log('Initializing setup');
  DebeVolverAPaginaCliente := False;
  Result := True;  
end;