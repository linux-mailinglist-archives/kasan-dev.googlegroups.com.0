Return-Path: <kasan-dev+bncBCALX3WVYQORBGGPZKCAMGQE5T4PA7A@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-oi1-x239.google.com (mail-oi1-x239.google.com [IPv6:2607:f8b0:4864:20::239])
	by mail.lfdr.de (Postfix) with ESMTPS id 25A07373D37
	for <lists+kasan-dev@lfdr.de>; Wed,  5 May 2021 16:11:38 +0200 (CEST)
Received: by mail-oi1-x239.google.com with SMTP id x6-20020acae0060000b02901e5030d8682sf927499oig.19
        for <lists+kasan-dev@lfdr.de>; Wed, 05 May 2021 07:11:38 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1620223897; cv=pass;
        d=google.com; s=arc-20160816;
        b=zV4CHoAp14nxQzmoaawMMu5+v2kphwiQrvTXV5PTlszpWHxmhVH63wYrF+0K3UHPDt
         TMtXKtzoE41FGEbIAnJvD6lfybACD+QlXac9czUk6/z5MsajD6iQQmFppM9OMjIJgAK4
         jgIG6WJRK7Dvo/0xTVsIjON+fsDosh1i9tw2pd8uC3v5JTqsni2Gp65o5MSefZY3DPvZ
         oPAIPP0GwOBMKAG69Qkza5+j9GTR6xptkqItlimRI3ac8pLKSUucsl9FW9PhieBZTfYl
         pCsNULc6Kw1xe02Q6AWoj79rBcKxvxajca7PNBufNmjAUv05Uv2ZIAhgmtKOUMgOMBxZ
         NjHQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:references
         :in-reply-to:message-id:date:cc:to:from:sender:dkim-signature;
        bh=wSQ/SMFVnaJwD/sWatjyqi1blo4sfjBp6JT4IaAAzWg=;
        b=vL/1VtkOE6tNIm8yK9vSY78Yn2CIOtVDET6ZpLlt9Y7VzTukXvm6QLokkgiFbvFsSC
         aMpeV0HdhF6lYa/O2W6SSpMdzxTNC3dWxjCNHqAL2PklHJqUkbVGAa478lCqFgYSeVIX
         CFcyVC+Xkx+qgj1UEF7EoFpeMozo17D2PJxImqp3oGul/CbVD3Egcknxy37aKfcFlvPY
         VwZlMdEhT/NjCP+cqf6LCBONCTsZLfQjCnxENDBDh6/s/AviWdY6AaI0kJdJvef/5R+k
         HV2BoEuyI6Dcn1R3ZoD0IMf6ufHFlXgsYOq3/pOLXZbxw6J2/0pGwdLa9uSw5BoGgGQV
         zaiQ==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:date:message-id:in-reply-to:references
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=wSQ/SMFVnaJwD/sWatjyqi1blo4sfjBp6JT4IaAAzWg=;
        b=f1ON48CSn8odKmME6EOWaXnH/qOorZ8MdU9d1HQvqZoYpLN1g9JnQX8TZ8ivO+1zfl
         V3+tZ3k2U0GK4lg0WgGi5DfC28me380+fRptbzBXx5mMDm7Akak/PadK8+2CMUrd/i3z
         uwhbCOVSv8zKc3k3DrWlUT+LL0YsAWjNSgjySKYLCDefzmMrGhqLy0z42TK0fGagxAnW
         lUMAa3LeCPLVecupmQD6NhzRgrBbdpkgz0jaH2geYvPdfl/YfOM75c8gNHJKBMjGmSiI
         QBuxRS+LKg1Deim4mvGTnxz9AazWOUsXfbEeq8sTV177XAvo19OLynWoMgaLPNYtfAVC
         XgKA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:date:message-id:in-reply-to
         :references:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=wSQ/SMFVnaJwD/sWatjyqi1blo4sfjBp6JT4IaAAzWg=;
        b=Nv+AhumtjVV8dUFmXz6majMp8IldxHv1Kc48RFvrkeYqw4LyLMHY1oDsEDTMHi93pQ
         ECeb64y65yfaiItwTzG6Hmn+tZuWD+uh7yrRAch/Vko/MAXSqVMipPCc22F6x1qWM5cK
         CztKrxKvWbu0LTyrJmGb4UkyeplS7Kkll95aTPDhBSG8wKrhm8opkH13u4shEs6YlGnX
         WHIc+PH6lugArWxAFTxHAjpio9+6GQH79UwPoSVU/5hGBvlG26ytexH5LeFulQ0YMhIQ
         o+7gFEzoq9Pi/wwPf+xg17MoYP4PUP9eQDuu2G9TrhLMm1e13CA9D8lJRzvq/S5e+wfv
         9vhw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531Yy3cFWbexfRUmBNCU8jHs5qVQLLVHoNIzR5HYGgjL1ekaMPd7
	KM7PPfD3REKlB1/YtSf6a/w=
X-Google-Smtp-Source: ABdhPJyQZuOZzZN2fN4ecqKZJDFDMgstv42shI+PI/HkYX9983TSBdtvLWno2LmJShqn+RZY19KJVg==
X-Received: by 2002:a9d:62d2:: with SMTP id z18mr1878045otk.78.1620223896992;
        Wed, 05 May 2021 07:11:36 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:aca:5c5:: with SMTP id 188ls5880164oif.6.gmail; Wed, 05 May
 2021 07:11:36 -0700 (PDT)
X-Received: by 2002:aca:bc89:: with SMTP id m131mr21948349oif.71.1620223896578;
        Wed, 05 May 2021 07:11:36 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1620223896; cv=none;
        d=google.com; s=arc-20160816;
        b=Tkst132X3momY7PG6r6CXIuiavmy97ug/jCGzrcKtykXYHK/VG+cInfxCDXGKcvZ0d
         XwZKHHsxkpXX/OOyAw01P7FHCfdrp79Ph2OI5dk/9E2DQdCYHUovRTmwxPYJDSSk18Nj
         dduZYz4E6bldGrPt5E0dyfaPdIxAmlf9l66ctI1tawWaotNNaBmT7cgjKH5PZg3kzgAQ
         PL7wPLJffOhLPDyRnqcgP6/6h15s4YAoeIw6fRBFijkIzpTvyBCahiVweU43GG70XVyE
         UCcLTDDkm9/W8FUGWnH49qYoo+wQ0Hh3GexxH3pylbgAwxpn+Eb94xAnTJgZZ4W6CfuP
         jP4g==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:content-transfer-encoding:mime-version:references
         :in-reply-to:message-id:date:cc:to:from;
        bh=7vtrCfxIOu2fQhQNeIJIPdwk2/cVsqzbwV4eCYL9U4U=;
        b=ZdT4+4V1mzizfPLBHA5Cl0G3JqBghqPyzPfVJqxsJitIOITpueTKaXHgijH0neJFo0
         ZmTwqckGwB6ZrXQmw9HxS6lJjgRdZV7J4aOpcwuC1/1rDmSFsi+s9+cd/3oVHGx/gk6K
         eZEOuwZqa9eNYeGVhXasZHnLKDF7ht+BosRoF3icGHCTVqnxIyeaKKZjMsPkLaZbDyBx
         Ic3CB9EwtqAn2YADYnMaQPMEQkKiS1CHI7Oethgq+ifEg3t+zY8JWXOTN2MNIYCOcOv3
         Ys4MfnLGdyr6LPD1TMf7luXN7HK0eyx3jST0lWEjp/nqIPJVzD+JVCnKBcB3Ic4bWAk6
         0zLw==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out03.mta.xmission.com (out03.mta.xmission.com. [166.70.13.233])
        by gmr-mx.google.com with ESMTPS id e13si706146oth.3.2021.05.05.07.11.36
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Wed, 05 May 2021 07:11:36 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as permitted sender) client-ip=166.70.13.233;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out03.mta.xmission.com with esmtps  (TLS1.2) tls TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFS-00CGdy-Uv; Wed, 05 May 2021 08:11:35 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95] helo=fess.int.ebiederm.org)
	by in01.mta.xmission.com with esmtpsa (TLS1.2:ECDHE_RSA_AES_128_GCM_SHA256:128)
	(Exim 4.87)
	(envelope-from <ebiederm@xmission.com>)
	id 1leIFQ-00007y-1r; Wed, 05 May 2021 08:11:34 -0600
From: "Eric W. Beiderman" <ebiederm@xmission.com>
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,
	Florian Weimer <fweimer@redhat.com>,
	"David S. Miller" <davem@davemloft.net>,
	Peter Zijlstra <peterz@infradead.org>,
	Ingo Molnar <mingo@kernel.org>,
	Thomas Gleixner <tglx@linutronix.de>,
	Peter Collingbourne <pcc@google.com>,
	Dmitry Vyukov <dvyukov@google.com>,
	Alexander Potapenko <glider@google.com>,
	sparclinux <sparclinux@vger.kernel.org>,
	linux-arch <linux-arch@vger.kernel.org>,
	Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,
	Linux API <linux-api@vger.kernel.org>,
	kasan-dev <kasan-dev@googlegroups.com>,
	"Eric W. Biederman" <ebiederm@xmission.com>
Date: Wed,  5 May 2021 09:10:56 -0500
Message-Id: <20210505141101.11519-7-ebiederm@xmission.com>
X-Mailer: git-send-email 2.30.1
In-Reply-To: <20210505141101.11519-1-ebiederm@xmission.com>
References: <m1tuni8ano.fsf_-_@fess.ebiederm.org>
 <20210505141101.11519-1-ebiederm@xmission.com>
MIME-Version: 1.0
X-XM-SPF: eid=1leIFQ-00007y-1r;;;mid=<20210505141101.11519-7-ebiederm@xmission.com>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1/7jJF34vwjC7Mp+WPJyjQAevO+zZaKWDI=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: 
X-Spam-Status: No, score=0.7 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,XMSubLong,
	XM_B_SpammyWords autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.5000]
	*  0.7 XMSubLong Long Subject
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
	*  0.2 XM_B_SpammyWords One or more commonly used spammy words
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: ;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 1668 ms - load_scoreonly_sql: 0.08 (0.0%),
	signal_user_changed: 12 (0.7%), b_tie_ro: 10 (0.6%), parse: 4.3 (0.3%),
	 extract_message_metadata: 38 (2.3%), get_uri_detail_list: 19 (1.1%),
	tests_pri_-1000: 16 (1.0%), tests_pri_-950: 1.61 (0.1%),
	tests_pri_-900: 1.29 (0.1%), tests_pri_-90: 189 (11.3%), check_bayes:
	187 (11.2%), b_tokenize: 40 (2.4%), b_tok_get_all: 15 (0.9%),
	b_comp_prob: 4.2 (0.2%), b_tok_touch_all: 120 (7.2%), b_finish: 1.18
	(0.1%), tests_pri_0: 1378 (82.6%), check_dkim_signature: 1.07 (0.1%),
	check_dkim_adsp: 3.4 (0.2%), poll_dns_idle: 0.50 (0.0%), tests_pri_10:
	2.8 (0.2%), tests_pri_500: 15 (0.9%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH v3 07/12] signal: Use dedicated helpers to send signals with si_trapno set
X-Spam-Flag: No
X-SA-Exim-Version: 4.2.1 (built Thu, 05 May 2016 13:38:54 -0600)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.233 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Content-Type: text/plain; charset="UTF-8"
Precedence: list
Mailing-list: list kasan-dev@googlegroups.com; contact kasan-dev+owners@googlegroups.com
List-ID: <kasan-dev.googlegroups.com>
X-Spam-Checked-In-Group: kasan-dev@googlegroups.com
X-Google-Group-Id: 358814495539
List-Post: <https://groups.google.com/group/kasan-dev/post>, <mailto:kasan-dev@googlegroups.com>
List-Help: <https://groups.google.com/support/>, <mailto:kasan-dev+help@googlegroups.com>
List-Archive: <https://groups.google.com/group/kasan-dev
List-Subscribe: <https://groups.google.com/group/kasan-dev/subscribe>, <mailto:kasan-dev+subscribe@googlegroups.com>
List-Unsubscribe: <mailto:googlegroups-manage+358814495539+unsubscribe@googlegroups.com>,
 <https://groups.google.com/group/kasan-dev/subscribe>

From: "Eric W. Biederman" <ebiederm@xmission.com>

Now that si_trapno is no longer expected to be present for every fault
reported using siginfo on alpha and sparc remove the trapno parameter
from force_sig_fault, force_sig_fault_to_task and send_sig_fault.

Add two new helpers force_sig_fault_trapno and send_sig_fautl_trapno
for those signals where trapno is expected to be set.

v1: https://lkml.kernel.org/r/m1eeers7q7.fsf_-_@fess.ebiederm.org
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 arch/alpha/kernel/osf_sys.c      |  2 +-
 arch/alpha/kernel/signal.c       |  4 +--
 arch/alpha/kernel/traps.c        | 24 ++++++++---------
 arch/alpha/mm/fault.c            |  4 +--
 arch/sparc/kernel/process_64.c   |  2 +-
 arch/sparc/kernel/sys_sparc_32.c |  2 +-
 arch/sparc/kernel/sys_sparc_64.c |  2 +-
 arch/sparc/kernel/traps_32.c     | 22 ++++++++--------
 arch/sparc/kernel/traps_64.c     | 44 ++++++++++++++------------------
 arch/sparc/kernel/unaligned_32.c |  2 +-
 arch/sparc/mm/fault_32.c         |  2 +-
 arch/sparc/mm/fault_64.c         |  2 +-
 include/linux/sched/signal.h     | 12 +++------
 kernel/signal.c                  | 41 +++++++++++++++++++++--------
 14 files changed, 88 insertions(+), 77 deletions(-)

diff --git a/arch/alpha/kernel/osf_sys.c b/arch/alpha/kernel/osf_sys.c
index d5367a1c6300..80c5d7fbe66a 100644
--- a/arch/alpha/kernel/osf_sys.c
+++ b/arch/alpha/kernel/osf_sys.c
@@ -878,7 +878,7 @@ SYSCALL_DEFINE5(osf_setsysinfo, unsigned long, op, void __user *, buffer,
 
 			send_sig_fault(SIGFPE, si_code,
 				       (void __user *)NULL,  /* FIXME */
-				       0, current);
+				       current);
  		}
 		return 0;
 	}
diff --git a/arch/alpha/kernel/signal.c b/arch/alpha/kernel/signal.c
index 948b89789da8..bc077babafab 100644
--- a/arch/alpha/kernel/signal.c
+++ b/arch/alpha/kernel/signal.c
@@ -219,7 +219,7 @@ do_sigreturn(struct sigcontext __user *sc)
 
 	/* Send SIGTRAP if we're single-stepping: */
 	if (ptrace_cancel_bpt (current)) {
-		send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *) regs->pc, 0,
+		send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *) regs->pc,
 			       current);
 	}
 	return;
@@ -247,7 +247,7 @@ do_rt_sigreturn(struct rt_sigframe __user *frame)
 
 	/* Send SIGTRAP if we're single-stepping: */
 	if (ptrace_cancel_bpt (current)) {
-		send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *) regs->pc, 0,
+		send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *) regs->pc,
 			       current);
 	}
 	return;
diff --git a/arch/alpha/kernel/traps.c b/arch/alpha/kernel/traps.c
index 921d4b6e4d95..0dddf9ecc1f4 100644
--- a/arch/alpha/kernel/traps.c
+++ b/arch/alpha/kernel/traps.c
@@ -227,7 +227,7 @@ do_entArith(unsigned long summary, unsigned long write_mask,
 	}
 	die_if_kernel("Arithmetic fault", regs, 0, NULL);
 
-	send_sig_fault(SIGFPE, si_code, (void __user *) regs->pc, 0, current);
+	send_sig_fault_trapno(SIGFPE, si_code, (void __user *) regs->pc, 0, current);
 }
 
 asmlinkage void
@@ -268,12 +268,12 @@ do_entIF(unsigned long type, struct pt_regs *regs)
 			regs->pc -= 4;	/* make pc point to former bpt */
 		}
 
-		send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc, 0,
+		send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc,
 			       current);
 		return;
 
 	      case 1: /* bugcheck */
-		send_sig_fault(SIGTRAP, TRAP_UNK, (void __user *) regs->pc, 0,
+		send_sig_fault(SIGTRAP, TRAP_UNK, (void __user *) regs->pc,
 			       current);
 		return;
 		
@@ -335,8 +335,8 @@ do_entIF(unsigned long type, struct pt_regs *regs)
 			break;
 		}
 
-		send_sig_fault(signo, code, (void __user *) regs->pc, regs->r16,
-			       current);
+		send_sig_fault_trapno(signo, code, (void __user *) regs->pc,
+				      regs->r16, current);
 		return;
 
 	      case 4: /* opDEC */
@@ -360,9 +360,9 @@ do_entIF(unsigned long type, struct pt_regs *regs)
 			if (si_code == 0)
 				return;
 			if (si_code > 0) {
-				send_sig_fault(SIGFPE, si_code,
-					       (void __user *) regs->pc, 0,
-					       current);
+				send_sig_fault_trapno(SIGFPE, si_code,
+						      (void __user *) regs->pc,
+						      0, current);
 				return;
 			}
 		}
@@ -387,7 +387,7 @@ do_entIF(unsigned long type, struct pt_regs *regs)
 		      ;
 	}
 
-	send_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)regs->pc, 0, current);
+	send_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)regs->pc, current);
 }
 
 /* There is an ifdef in the PALcode in MILO that enables a 
@@ -402,7 +402,7 @@ do_entDbg(struct pt_regs *regs)
 {
 	die_if_kernel("Instruction fault", regs, 0, NULL);
 
-	force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)regs->pc, 0);
+	force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)regs->pc);
 }
 
 
@@ -964,12 +964,12 @@ do_entUnaUser(void __user * va, unsigned long opcode,
 			si_code = SEGV_MAPERR;
 		mmap_read_unlock(mm);
 	}
-	send_sig_fault(SIGSEGV, si_code, va, 0, current);
+	send_sig_fault(SIGSEGV, si_code, va, current);
 	return;
 
 give_sigbus:
 	regs->pc -= 4;
-	send_sig_fault(SIGBUS, BUS_ADRALN, va, 0, current);
+	send_sig_fault(SIGBUS, BUS_ADRALN, va, current);
 	return;
 }
 
diff --git a/arch/alpha/mm/fault.c b/arch/alpha/mm/fault.c
index 09172f017efc..eee5102c3d88 100644
--- a/arch/alpha/mm/fault.c
+++ b/arch/alpha/mm/fault.c
@@ -219,13 +219,13 @@ do_page_fault(unsigned long address, unsigned long mmcsr,
 	mmap_read_unlock(mm);
 	/* Send a sigbus, regardless of whether we were in kernel
 	   or user mode.  */
-	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *) address, 0);
+	force_sig_fault(SIGBUS, BUS_ADRERR, (void __user *) address);
 	if (!user_mode(regs))
 		goto no_context;
 	return;
 
  do_sigsegv:
-	force_sig_fault(SIGSEGV, si_code, (void __user *) address, 0);
+	force_sig_fault(SIGSEGV, si_code, (void __user *) address);
 	return;
 
 #ifdef CONFIG_ALPHA_LARGE_VMALLOC
diff --git a/arch/sparc/kernel/process_64.c b/arch/sparc/kernel/process_64.c
index 7afd0a859a78..29e67854d5a4 100644
--- a/arch/sparc/kernel/process_64.c
+++ b/arch/sparc/kernel/process_64.c
@@ -518,7 +518,7 @@ void synchronize_user_stack(void)
 
 static void stack_unaligned(unsigned long sp)
 {
-	force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *) sp, 0);
+	force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *) sp);
 }
 
 static const char uwfault32[] = KERN_INFO \
diff --git a/arch/sparc/kernel/sys_sparc_32.c b/arch/sparc/kernel/sys_sparc_32.c
index be77538bc038..082a551897ed 100644
--- a/arch/sparc/kernel/sys_sparc_32.c
+++ b/arch/sparc/kernel/sys_sparc_32.c
@@ -151,7 +151,7 @@ sparc_breakpoint (struct pt_regs *regs)
 #ifdef DEBUG_SPARC_BREAKPOINT
         printk ("TRAP: Entering kernel PC=%x, nPC=%x\n", regs->pc, regs->npc);
 #endif
-	force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc, 0);
+	force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc);
 
 #ifdef DEBUG_SPARC_BREAKPOINT
 	printk ("TRAP: Returning to space: PC=%x nPC=%x\n", regs->pc, regs->npc);
diff --git a/arch/sparc/kernel/sys_sparc_64.c b/arch/sparc/kernel/sys_sparc_64.c
index 6b92fadb6ec7..1e9a9e016237 100644
--- a/arch/sparc/kernel/sys_sparc_64.c
+++ b/arch/sparc/kernel/sys_sparc_64.c
@@ -514,7 +514,7 @@ asmlinkage void sparc_breakpoint(struct pt_regs *regs)
 #ifdef DEBUG_SPARC_BREAKPOINT
         printk ("TRAP: Entering kernel PC=%lx, nPC=%lx\n", regs->tpc, regs->tnpc);
 #endif
-	force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->tpc, 0);
+	force_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->tpc);
 #ifdef DEBUG_SPARC_BREAKPOINT
 	printk ("TRAP: Returning to space: PC=%lx nPC=%lx\n", regs->tpc, regs->tnpc);
 #endif
diff --git a/arch/sparc/kernel/traps_32.c b/arch/sparc/kernel/traps_32.c
index 247a0d9683b2..5630e5a395e0 100644
--- a/arch/sparc/kernel/traps_32.c
+++ b/arch/sparc/kernel/traps_32.c
@@ -102,8 +102,8 @@ void do_hw_interrupt(struct pt_regs *regs, unsigned long type)
 	if(regs->psr & PSR_PS)
 		die_if_kernel("Kernel bad trap", regs);
 
-	force_sig_fault(SIGILL, ILL_ILLTRP,
-			(void __user *)regs->pc, type - 0x80);
+	force_sig_fault_trapno(SIGILL, ILL_ILLTRP,
+			       (void __user *)regs->pc, type - 0x80);
 }
 
 void do_illegal_instruction(struct pt_regs *regs, unsigned long pc, unsigned long npc,
@@ -116,7 +116,7 @@ void do_illegal_instruction(struct pt_regs *regs, unsigned long pc, unsigned lon
 	       regs->pc, *(unsigned long *)regs->pc);
 #endif
 
-	send_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)pc, 0, current);
+	send_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)pc, current);
 }
 
 void do_priv_instruction(struct pt_regs *regs, unsigned long pc, unsigned long npc,
@@ -124,7 +124,7 @@ void do_priv_instruction(struct pt_regs *regs, unsigned long pc, unsigned long n
 {
 	if(psr & PSR_PS)
 		die_if_kernel("Penguin instruction from Penguin mode??!?!", regs);
-	send_sig_fault(SIGILL, ILL_PRVOPC, (void __user *)pc, 0, current);
+	send_sig_fault(SIGILL, ILL_PRVOPC, (void __user *)pc, current);
 }
 
 /* XXX User may want to be allowed to do this. XXX */
@@ -145,7 +145,7 @@ void do_memaccess_unaligned(struct pt_regs *regs, unsigned long pc, unsigned lon
 #endif
 	send_sig_fault(SIGBUS, BUS_ADRALN,
 		       /* FIXME: Should dig out mna address */ (void *)0,
-		       0, current);
+		       current);
 }
 
 static unsigned long init_fsr = 0x0UL;
@@ -291,7 +291,7 @@ void do_fpe_trap(struct pt_regs *regs, unsigned long pc, unsigned long npc,
 		else if (fsr & 0x01)
 			code = FPE_FLTRES;
 	}
-	send_sig_fault(SIGFPE, code, (void __user *)pc, 0, fpt);
+	send_sig_fault(SIGFPE, code, (void __user *)pc, fpt);
 #ifndef CONFIG_SMP
 	last_task_used_math = NULL;
 #endif
@@ -305,7 +305,7 @@ void handle_tag_overflow(struct pt_regs *regs, unsigned long pc, unsigned long n
 {
 	if(psr & PSR_PS)
 		die_if_kernel("Penguin overflow trap from kernel mode", regs);
-	send_sig_fault(SIGEMT, EMT_TAGOVF, (void __user *)pc, 0, current);
+	send_sig_fault(SIGEMT, EMT_TAGOVF, (void __user *)pc, current);
 }
 
 void handle_watchpoint(struct pt_regs *regs, unsigned long pc, unsigned long npc,
@@ -327,13 +327,13 @@ void handle_reg_access(struct pt_regs *regs, unsigned long pc, unsigned long npc
 	printk("Register Access Exception at PC %08lx NPC %08lx PSR %08lx\n",
 	       pc, npc, psr);
 #endif
-	force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)pc, 0);
+	force_sig_fault(SIGBUS, BUS_OBJERR, (void __user *)pc);
 }
 
 void handle_cp_disabled(struct pt_regs *regs, unsigned long pc, unsigned long npc,
 			unsigned long psr)
 {
-	send_sig_fault(SIGILL, ILL_COPROC, (void __user *)pc, 0, current);
+	send_sig_fault(SIGILL, ILL_COPROC, (void __user *)pc, current);
 }
 
 void handle_cp_exception(struct pt_regs *regs, unsigned long pc, unsigned long npc,
@@ -343,13 +343,13 @@ void handle_cp_exception(struct pt_regs *regs, unsigned long pc, unsigned long n
 	printk("Co-Processor Exception at PC %08lx NPC %08lx PSR %08lx\n",
 	       pc, npc, psr);
 #endif
-	send_sig_fault(SIGILL, ILL_COPROC, (void __user *)pc, 0, current);
+	send_sig_fault(SIGILL, ILL_COPROC, (void __user *)pc, current);
 }
 
 void handle_hw_divzero(struct pt_regs *regs, unsigned long pc, unsigned long npc,
 		       unsigned long psr)
 {
-	send_sig_fault(SIGFPE, FPE_INTDIV, (void __user *)pc, 0, current);
+	send_sig_fault(SIGFPE, FPE_INTDIV, (void __user *)pc, current);
 }
 
 #ifdef CONFIG_DEBUG_BUGVERBOSE
diff --git a/arch/sparc/kernel/traps_64.c b/arch/sparc/kernel/traps_64.c
index a850dccd78ea..6863025ed56d 100644
--- a/arch/sparc/kernel/traps_64.c
+++ b/arch/sparc/kernel/traps_64.c
@@ -107,8 +107,8 @@ void bad_trap(struct pt_regs *regs, long lvl)
 		regs->tpc &= 0xffffffff;
 		regs->tnpc &= 0xffffffff;
 	}
-	force_sig_fault(SIGILL, ILL_ILLTRP,
-			(void __user *)regs->tpc, lvl);
+	force_sig_fault_trapno(SIGILL, ILL_ILLTRP,
+			       (void __user *)regs->tpc, lvl);
 }
 
 void bad_trap_tl1(struct pt_regs *regs, long lvl)
@@ -201,8 +201,7 @@ void spitfire_insn_access_exception(struct pt_regs *regs, unsigned long sfsr, un
 		regs->tpc &= 0xffffffff;
 		regs->tnpc &= 0xffffffff;
 	}
-	force_sig_fault(SIGSEGV, SEGV_MAPERR,
-			(void __user *)regs->tpc, 0);
+	force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)regs->tpc);
 out:
 	exception_exit(prev_state);
 }
@@ -237,7 +236,7 @@ void sun4v_insn_access_exception(struct pt_regs *regs, unsigned long addr, unsig
 		regs->tpc &= 0xffffffff;
 		regs->tnpc &= 0xffffffff;
 	}
-	force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *) addr, 0);
+	force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *) addr);
 }
 
 void sun4v_insn_access_exception_tl1(struct pt_regs *regs, unsigned long addr, unsigned long type_ctx)
@@ -321,7 +320,7 @@ void spitfire_data_access_exception(struct pt_regs *regs, unsigned long sfsr, un
 	if (is_no_fault_exception(regs))
 		return;
 
-	force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)sfar, 0);
+	force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)sfar);
 out:
 	exception_exit(prev_state);
 }
@@ -385,13 +384,13 @@ void sun4v_data_access_exception(struct pt_regs *regs, unsigned long addr, unsig
 	 */
 	switch (type) {
 	case HV_FAULT_TYPE_INV_ASI:
-		force_sig_fault(SIGILL, ILL_ILLADR, (void __user *)addr, 0);
+		force_sig_fault(SIGILL, ILL_ILLADR, (void __user *)addr);
 		break;
 	case HV_FAULT_TYPE_MCD_DIS:
-		force_sig_fault(SIGSEGV, SEGV_ACCADI, (void __user *)addr, 0);
+		force_sig_fault(SIGSEGV, SEGV_ACCADI, (void __user *)addr);
 		break;
 	default:
-		force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)addr, 0);
+		force_sig_fault(SIGSEGV, SEGV_MAPERR, (void __user *)addr);
 		break;
 	}
 }
@@ -568,7 +567,7 @@ static void spitfire_ue_log(unsigned long afsr, unsigned long afar, unsigned lon
 		regs->tpc &= 0xffffffff;
 		regs->tnpc &= 0xffffffff;
 	}
-	force_sig_fault(SIGBUS, BUS_OBJERR, (void *)0, 0);
+	force_sig_fault(SIGBUS, BUS_OBJERR, (void *)0);
 }
 
 void spitfire_access_error(struct pt_regs *regs, unsigned long status_encoded, unsigned long afar)
@@ -2069,8 +2068,7 @@ void do_mcd_err(struct pt_regs *regs, struct sun4v_error_entry ent)
 	/* Send SIGSEGV to the userspace process with the right signal
 	 * code
 	 */
-	force_sig_fault(SIGSEGV, SEGV_ADIDERR, (void __user *)ent.err_raddr,
-			0);
+	force_sig_fault(SIGSEGV, SEGV_ADIDERR, (void __user *)ent.err_raddr);
 }
 
 /* We run with %pil set to PIL_NORMAL_MAX and PSTATE_IE enabled in %pstate.
@@ -2184,7 +2182,7 @@ bool sun4v_nonresum_error_user_handled(struct pt_regs *regs,
 	}
 	if (attrs & SUN4V_ERR_ATTRS_PIO) {
 		force_sig_fault(SIGBUS, BUS_ADRERR,
-				(void __user *)sun4v_get_vaddr(regs), 0);
+				(void __user *)sun4v_get_vaddr(regs));
 		return true;
 	}
 
@@ -2340,8 +2338,7 @@ static void do_fpe_common(struct pt_regs *regs)
 			else if (fsr & 0x01)
 				code = FPE_FLTRES;
 		}
-		force_sig_fault(SIGFPE, code,
-				(void __user *)regs->tpc, 0);
+		force_sig_fault(SIGFPE, code, (void __user *)regs->tpc);
 	}
 }
 
@@ -2395,8 +2392,7 @@ void do_tof(struct pt_regs *regs)
 		regs->tpc &= 0xffffffff;
 		regs->tnpc &= 0xffffffff;
 	}
-	force_sig_fault(SIGEMT, EMT_TAGOVF,
-			(void __user *)regs->tpc, 0);
+	force_sig_fault(SIGEMT, EMT_TAGOVF, (void __user *)regs->tpc);
 out:
 	exception_exit(prev_state);
 }
@@ -2415,8 +2411,7 @@ void do_div0(struct pt_regs *regs)
 		regs->tpc &= 0xffffffff;
 		regs->tnpc &= 0xffffffff;
 	}
-	force_sig_fault(SIGFPE, FPE_INTDIV,
-			(void __user *)regs->tpc, 0);
+	force_sig_fault(SIGFPE, FPE_INTDIV, (void __user *)regs->tpc);
 out:
 	exception_exit(prev_state);
 }
@@ -2612,7 +2607,7 @@ void do_illegal_instruction(struct pt_regs *regs)
 			}
 		}
 	}
-	force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)pc, 0);
+	force_sig_fault(SIGILL, ILL_ILLOPC, (void __user *)pc);
 out:
 	exception_exit(prev_state);
 }
@@ -2632,7 +2627,7 @@ void mem_address_unaligned(struct pt_regs *regs, unsigned long sfar, unsigned lo
 	if (is_no_fault_exception(regs))
 		return;
 
-	force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *)sfar, 0);
+	force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *)sfar);
 out:
 	exception_exit(prev_state);
 }
@@ -2650,7 +2645,7 @@ void sun4v_do_mna(struct pt_regs *regs, unsigned long addr, unsigned long type_c
 	if (is_no_fault_exception(regs))
 		return;
 
-	force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *) addr, 0);
+	force_sig_fault(SIGBUS, BUS_ADRALN, (void __user *) addr);
 }
 
 /* sun4v_mem_corrupt_detect_precise() - Handle precise exception on an ADI
@@ -2697,7 +2692,7 @@ void sun4v_mem_corrupt_detect_precise(struct pt_regs *regs, unsigned long addr,
 		regs->tpc &= 0xffffffff;
 		regs->tnpc &= 0xffffffff;
 	}
-	force_sig_fault(SIGSEGV, SEGV_ADIPERR, (void __user *)addr, 0);
+	force_sig_fault(SIGSEGV, SEGV_ADIPERR, (void __user *)addr);
 }
 
 void do_privop(struct pt_regs *regs)
@@ -2712,8 +2707,7 @@ void do_privop(struct pt_regs *regs)
 		regs->tpc &= 0xffffffff;
 		regs->tnpc &= 0xffffffff;
 	}
-	force_sig_fault(SIGILL, ILL_PRVOPC,
-			(void __user *)regs->tpc, 0);
+	force_sig_fault(SIGILL, ILL_PRVOPC, (void __user *)regs->tpc);
 out:
 	exception_exit(prev_state);
 }
diff --git a/arch/sparc/kernel/unaligned_32.c b/arch/sparc/kernel/unaligned_32.c
index ef5c5207c9ff..455f0258c745 100644
--- a/arch/sparc/kernel/unaligned_32.c
+++ b/arch/sparc/kernel/unaligned_32.c
@@ -278,5 +278,5 @@ asmlinkage void user_unaligned_trap(struct pt_regs *regs, unsigned int insn)
 {
 	send_sig_fault(SIGBUS, BUS_ADRALN,
 		       (void __user *)safe_compute_effective_address(regs, insn),
-		       0, current);
+		       current);
 }
diff --git a/arch/sparc/mm/fault_32.c b/arch/sparc/mm/fault_32.c
index de2031c2b2d7..fa858626b85b 100644
--- a/arch/sparc/mm/fault_32.c
+++ b/arch/sparc/mm/fault_32.c
@@ -83,7 +83,7 @@ static void __do_fault_siginfo(int code, int sig, struct pt_regs *regs,
 		show_signal_msg(regs, sig, code,
 				addr, current);
 
-	force_sig_fault(sig, code, (void __user *) addr, 0);
+	force_sig_fault(sig, code, (void __user *) addr);
 }
 
 static unsigned long compute_si_addr(struct pt_regs *regs, int text_fault)
diff --git a/arch/sparc/mm/fault_64.c b/arch/sparc/mm/fault_64.c
index 0a6bcc85fba7..9a9652a15fed 100644
--- a/arch/sparc/mm/fault_64.c
+++ b/arch/sparc/mm/fault_64.c
@@ -176,7 +176,7 @@ static void do_fault_siginfo(int code, int sig, struct pt_regs *regs,
 	if (unlikely(show_unhandled_signals))
 		show_signal_msg(regs, sig, code, addr, current);
 
-	force_sig_fault(sig, code, (void __user *) addr, 0);
+	force_sig_fault(sig, code, (void __user *) addr);
 }
 
 static unsigned int get_fault_insn(struct pt_regs *regs, unsigned int insn)
diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index 3f6a0fcaa10c..7daa425f3055 100644
--- a/include/linux/sched/signal.h
+++ b/include/linux/sched/signal.h
@@ -298,11 +298,6 @@ static inline void kernel_signal_stop(void)
 
 	schedule();
 }
-#ifdef __ARCH_SI_TRAPNO
-# define ___ARCH_SI_TRAPNO(_a1) , _a1
-#else
-# define ___ARCH_SI_TRAPNO(_a1)
-#endif
 #ifdef __ia64__
 # define ___ARCH_SI_IA64(_a1, _a2, _a3) , _a1, _a2, _a3
 #else
@@ -310,14 +305,11 @@ static inline void kernel_signal_stop(void)
 #endif
 
 int force_sig_fault_to_task(int sig, int code, void __user *addr
-	___ARCH_SI_TRAPNO(int trapno)
 	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
 	, struct task_struct *t);
 int force_sig_fault(int sig, int code, void __user *addr
-	___ARCH_SI_TRAPNO(int trapno)
 	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr));
 int send_sig_fault(int sig, int code, void __user *addr
-	___ARCH_SI_TRAPNO(int trapno)
 	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
 	, struct task_struct *t);
 
@@ -327,6 +319,10 @@ int send_sig_mceerr(int code, void __user *, short, struct task_struct *);
 int force_sig_bnderr(void __user *addr, void __user *lower, void __user *upper);
 int force_sig_pkuerr(void __user *addr, u32 pkey);
 
+int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno);
+int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
+			  struct task_struct *task);
+
 int force_sig_ptrace_errno_trap(int errno, void __user *addr);
 
 extern int send_sig_info(int, struct kernel_siginfo *, struct task_struct *);
diff --git a/kernel/signal.c b/kernel/signal.c
index 3d3ba7949788..7eaa8d84db4c 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1651,7 +1651,6 @@ void force_sigsegv(int sig)
 }
 
 int force_sig_fault_to_task(int sig, int code, void __user *addr
-	___ARCH_SI_TRAPNO(int trapno)
 	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
 	, struct task_struct *t)
 {
@@ -1662,9 +1661,6 @@ int force_sig_fault_to_task(int sig, int code, void __user *addr
 	info.si_errno = 0;
 	info.si_code  = code;
 	info.si_addr  = addr;
-#ifdef __ARCH_SI_TRAPNO
-	info.si_trapno = trapno;
-#endif
 #ifdef __ia64__
 	info.si_imm = imm;
 	info.si_flags = flags;
@@ -1674,16 +1670,13 @@ int force_sig_fault_to_task(int sig, int code, void __user *addr
 }
 
 int force_sig_fault(int sig, int code, void __user *addr
-	___ARCH_SI_TRAPNO(int trapno)
 	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr))
 {
 	return force_sig_fault_to_task(sig, code, addr
-				       ___ARCH_SI_TRAPNO(trapno)
 				       ___ARCH_SI_IA64(imm, flags, isr), current);
 }
 
 int send_sig_fault(int sig, int code, void __user *addr
-	___ARCH_SI_TRAPNO(int trapno)
 	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
 	, struct task_struct *t)
 {
@@ -1694,9 +1687,6 @@ int send_sig_fault(int sig, int code, void __user *addr
 	info.si_errno = 0;
 	info.si_code  = code;
 	info.si_addr  = addr;
-#ifdef __ARCH_SI_TRAPNO
-	info.si_trapno = trapno;
-#endif
 #ifdef __ia64__
 	info.si_imm = imm;
 	info.si_flags = flags;
@@ -1763,6 +1753,37 @@ int force_sig_pkuerr(void __user *addr, u32 pkey)
 }
 #endif
 
+#if IS_ENABLED(CONFIG_SPARC)
+int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
+{
+	struct kernel_siginfo info;
+
+	clear_siginfo(&info);
+	info.si_signo = sig;
+	info.si_errno = 0;
+	info.si_code  = code;
+	info.si_addr  = addr;
+	info.si_trapno = trapno;
+	return force_sig_info(&info);
+}
+#endif
+
+#if IS_ENABLED(CONFIG_ALPHA)
+int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
+			  struct task_struct *t)
+{
+	struct kernel_siginfo info;
+
+	clear_siginfo(&info);
+	info.si_signo = sig;
+	info.si_errno = 0;
+	info.si_code  = code;
+	info.si_addr  = addr;
+	info.si_trapno = trapno;
+	return send_sig_info(info.si_signo, &info, t);
+}
+#endif
+
 /* For the crazy architectures that include trap information in
  * the errno field, instead of an actual errno value.
  */
-- 
2.30.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/20210505141101.11519-7-ebiederm%40xmission.com.
