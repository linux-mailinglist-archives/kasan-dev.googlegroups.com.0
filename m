Return-Path: <kasan-dev+bncBCALX3WVYQORBP7VYGDQMGQEANEUXGY@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-pf1-x439.google.com (mail-pf1-x439.google.com [IPv6:2607:f8b0:4864:20::439])
	by mail.lfdr.de (Postfix) with ESMTPS id DB5223CA529
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 20:13:20 +0200 (CEST)
Received: by mail-pf1-x439.google.com with SMTP id s187-20020a625ec40000b02903288ce43fc0sf4900622pfb.7
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 11:13:20 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626372799; cv=pass;
        d=google.com; s=arc-20160816;
        b=e9uLfr2RZWOlYTryiQJ8wsJDDfaAFHWfDzq1z5YbOdtM3CpKCdyo6/uLX+zUyPjWI/
         /BuL89LwxAtO3giDTxdd5ZaOWLlFb0eUtUX+aJ95ohkV6fcHGiuSUikH50hIzSVXMAua
         ahMOcC7KrpzKqZ/kXnKVPETp5v+ctEDF607twnCNc4WUZ3v2gbWERpqLiK0OWu5ylK1M
         SoSFWCHwhny2dF/sKf9RZ+pV/iSSaKvJsVlyPsMXBOE9pzsW+v2wMOgukp3w02ROcAyM
         oonXSHMoTbCLyzfogznnqeNHR/Vbh970Xgf+2BqlXBEpfoL6pJKMQFQAcJ7/UlOxxf7z
         aHWQ==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=5BMYfvk+D7JF2jUhih2CNMhT/E+mWwdZ8bjEIpJmhrw=;
        b=ih1pMSVqpyA/3Lr7NEL3wR79U1PLV3w0dp44Xf46qW3N3+C8bKpXDchgh/FGfi2fWH
         a/yXu40GYT7CBBUNiSyuH26zrRZcYthNxLtYuqw8ZnOfNhWLG7onGc1X8dHAAr6yInr9
         BfA5umFUTg8/k/G8JkJfwsHn27MZAAWx2P22cpZs/CWS42NIITHjllc5pniobbK45Ti6
         4YcXOr2Ns0Ov8GZduAgSwDRAYQnfdQDc5rHOLbmaZyP32K66Y3gk5MSQP8ctTUDHB6nX
         XwNwH1Jh4M2A75hCE92kW1+DB/4abXslomwHX9RQUs/oKXcjDD/est/rlr2sIB+nwoDT
         APlg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=5BMYfvk+D7JF2jUhih2CNMhT/E+mWwdZ8bjEIpJmhrw=;
        b=MPTpIJwAsIXl+n842kNTIqzerZbc1lltlZvaGXdvn7Ug5aRRzGpHQZuilvamibd7ZV
         r1ZpELMnO9/Tt0MlhzKqrI3uBV5E8GyxTWCh+IhCYzZa766nbxIBj1VAuyCeM9PNbGtY
         1/6byZf6fW1bAavVt4c0EszVZ1YPMaqO/DSqDZ/PPtj2hcCLm3mjRHHGr1d8AgvoU6Me
         ndyIZzpwQsYJqJ80lPFbG2MansPe3R43ocJrZHnGIOh+D6PilTbbPzYVZRpwdhvbi+UP
         H3E7dGaVc6ySb3O9wmZYP9GsXcwlDJtwAn+hhaTeUgGwEzdaZF+pjarh0KAacYK6BxbM
         K+mA==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=5BMYfvk+D7JF2jUhih2CNMhT/E+mWwdZ8bjEIpJmhrw=;
        b=WAemMBu9cz6DvQ0iku+f5LeAlMXgZBT32QZ+lQjiEb5cPGSxYmK89l9J72OoPw/iy3
         yv7bu8QGDDvDSmCcnG16+Wh7sPkOTZg6HUD3IlkhurkJ5MWdjJB9dKifsaQRErvrw7Ho
         w2J3rE6HWVahZTyLMkonrabPAOSSrgJt4CVZ8Cdn4MRGWnzBCVmQVmAIDLRW/IEUBV8d
         crAJHQC6TmFkaco7jAOIKAUbFWHXfCkPt3WO8YNcZzSHh/X2jnAecrGGtGr3IFU4KKK8
         NDabVJ7fhspeYvqiy9B165sr/FP55KT/sv78hnOtFZS1+0dDWZeWfAMoEidQFUHtRwp3
         OZ/g==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM531BKWQ6pOumnkxmgMZFiaccNcXJJSZbIcAR6tVBstTEHyCrPRoc
	cZPs+XUWLSOXiYC5wvVI5xk=
X-Google-Smtp-Source: ABdhPJyMIYuizOFB+0wYw08K5Tlky+KZ7+LWmiPDpaFeOYY/+mT0t4qEGr0pAN+ZN9LRzhfbtDnUqQ==
X-Received: by 2002:a17:90a:f698:: with SMTP id cl24mr11116505pjb.79.1626372799630;
        Thu, 15 Jul 2021 11:13:19 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a05:6a00:1824:: with SMTP id y36ls3302100pfa.11.gmail; Thu,
 15 Jul 2021 11:13:19 -0700 (PDT)
X-Received: by 2002:a63:f516:: with SMTP id w22mr5913257pgh.188.1626372799049;
        Thu, 15 Jul 2021 11:13:19 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626372799; cv=none;
        d=google.com; s=arc-20160816;
        b=UKxkeZ8szJi7rnY+0Xs7NpUfMhtQmbtlDDZjx6ugw6swyPGC9Ss7cCtd+G6afZ0WH6
         r4loT99xuPPab4CxanlO+a4t1ULhHIngjiFi4f4VcvPZ8+ry+OORjKlkhROCW6o7naLG
         KJ/ByHq50Bwl+cc56A4YNPmhrGHyVMzS11/Arsd/kWUZhz67jVvGiUckMHbISSINQIt4
         qaTPUufpH3dgYHs1mDbboS8GmRk6n5tSxDKdZNOCVgg/+YutoAk6tGwMGpx4VsDL8uhm
         rycB9AjGoz63hXpBFuopuRTXlRfn+Gabow1eII1O1d7FeGa1J4VFvxEUYBeqZ7jA8Rri
         IeVQ==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=Y3uDHRWbik90J1Q4+jdPZcyo3RIRXKU4xpj8glAmWn4=;
        b=l3nDa9abD6Ht5GnKP5WeNelqtzn9mbhPfR6hg9rZlTW4zmBMPXyNDyiz3sX9UPNdAZ
         r39k/Qk8TOV4j45BchhR2a/k6WGsRtUmw+akJl027vWuY2Vxp6o/pWb33dit3/gczoU9
         rVhAq3XvaNaHt5nlwz5Hm4vT+DaQttykYlbg9qFtf6auwMaYRWDmQoBUfEztYSD07vIm
         VVqdpUlWe2ynN8LV60E/ejxSgaNHpZOPpMx8TDA8a3mWhJ6TAwbsUBrA3mtt/2eOM0vX
         sBXtX9NhMUX8PZ62pDlTI2w81gu4EKWCBcsLCQddIm+6OD6vo3u2raDCli5FCPs/7oZq
         9qqg==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id dw12si590772pjb.3.2021.07.15.11.13.19
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jul 2021 11:13:19 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in01.mta.xmission.com ([166.70.13.51])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45rK-00Bf5I-3o; Thu, 15 Jul 2021 12:13:18 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:57124 helo=email.xmission.com)
	by in01.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45rI-00CTRy-RF; Thu, 15 Jul 2021 12:13:17 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133>
Date: Thu, 15 Jul 2021 13:13:10 -0500
In-Reply-To: <87a6mnzbx2.fsf_-_@disp2133> (Eric W. Biederman's message of
	"Thu, 15 Jul 2021 13:09:45 -0500")
Message-ID: <87bl73xx6x.fsf_-_@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1m45rI-00CTRy-RF;;;mid=<87bl73xx6x.fsf_-_@disp2133>;;;hst=in01.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX19Q5lCKVhgwZDktS5VnfDpWALc25KTcAGQ=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa07.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,XMNoVowels,
	XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4987]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa07 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa07 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 689 ms - load_scoreonly_sql: 0.05 (0.0%),
	signal_user_changed: 11 (1.6%), b_tie_ro: 10 (1.4%), parse: 1.03
	(0.1%), extract_message_metadata: 14 (2.0%), get_uri_detail_list: 2.8
	(0.4%), tests_pri_-1000: 15 (2.2%), tests_pri_-950: 1.34 (0.2%),
	tests_pri_-900: 1.04 (0.2%), tests_pri_-90: 153 (22.1%), check_bayes:
	150 (21.8%), b_tokenize: 22 (3.2%), b_tok_get_all: 12 (1.7%),
	b_comp_prob: 3.5 (0.5%), b_tok_touch_all: 108 (15.7%), b_finish: 1.57
	(0.2%), tests_pri_0: 426 (61.8%), check_dkim_signature: 0.90 (0.1%),
	check_dkim_adsp: 3.0 (0.4%), poll_dns_idle: 0.63 (0.1%), tests_pri_10:
	2.3 (0.3%), tests_pri_500: 61 (8.9%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 6/6] signal: Remove the generic __ARCH_SI_TRAPNO support
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in01.mta.xmission.com)
X-Original-Sender: ebiederm@xmission.com
X-Original-Authentication-Results: gmr-mx.google.com;       spf=pass
 (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as
 permitted sender) smtp.mailfrom=ebiederm@xmission.com;       dmarc=pass
 (p=NONE sp=NONE dis=NONE) header.from=xmission.com
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


Now that __ARCH_SI_TRAPNO is no longer set by any architecture remove
all of the code it enabled from the kernel.

On alpha and sparc a more explict approach of using
send_sig_fault_trapno or force_sig_fault_trapno in the very limited
circumstances where si_trapno was set to a non-zero value.

The generic support that is being removed always set si_trapno on all
fault signals.  With only SIGILL ILL_ILLTRAP on sparc and SIGFPE and
SIGTRAP TRAP_UNK on alpla providing si_trapno values asking all senders
of fault signals to provide an si_trapno value does not make sense.

Making si_trapno an ordinary extension of the fault siginfo layout has
enabled the architecture generic implementation of SIGTRAP TRAP_PERF,
and enables other faulting signals to grow architecture generic
senders as well.

v1: https://lkml.kernel.org/r/m18s4zs7nu.fsf_-_@fess.ebiederm.org
v2: https://lkml.kernel.org/r/20210505141101.11519-8-ebiederm@xmission.com
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 arch/mips/include/uapi/asm/siginfo.h |  2 --
 include/linux/sched/signal.h         |  8 --------
 kernel/signal.c                      | 14 --------------
 3 files changed, 24 deletions(-)

diff --git a/arch/mips/include/uapi/asm/siginfo.h b/arch/mips/include/uapi/asm/siginfo.h
index c34c7eef0a1c..8cb8bd061a68 100644
--- a/arch/mips/include/uapi/asm/siginfo.h
+++ b/arch/mips/include/uapi/asm/siginfo.h
@@ -10,9 +10,7 @@
 #ifndef _UAPI_ASM_SIGINFO_H
 #define _UAPI_ASM_SIGINFO_H
 
-
 #define __ARCH_SIGEV_PREAMBLE_SIZE (sizeof(long) + 2*sizeof(int))
-#undef __ARCH_SI_TRAPNO /* exception code needs to fill this ...  */
 
 #define __ARCH_HAS_SWAPPED_SIGINFO
 
diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index 6657184cef07..928e0025d358 100644
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
 
diff --git a/kernel/signal.c b/kernel/signal.c
index ae06a424aa72..2181423e562a 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1666,7 +1666,6 @@ void force_sigsegv(int sig)
 }
 
 int force_sig_fault_to_task(int sig, int code, void __user *addr
-	___ARCH_SI_TRAPNO(int trapno)
 	___ARCH_SI_IA64(int imm, unsigned int flags, unsigned long isr)
 	, struct task_struct *t)
 {
@@ -1677,9 +1676,6 @@ int force_sig_fault_to_task(int sig, int code, void __user *addr
 	info.si_errno = 0;
 	info.si_code  = code;
 	info.si_addr  = addr;
-#ifdef __ARCH_SI_TRAPNO
-	info.si_trapno = trapno;
-#endif
 #ifdef __ia64__
 	info.si_imm = imm;
 	info.si_flags = flags;
@@ -1689,16 +1685,13 @@ int force_sig_fault_to_task(int sig, int code, void __user *addr
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
@@ -1709,9 +1702,6 @@ int send_sig_fault(int sig, int code, void __user *addr
 	info.si_errno = 0;
 	info.si_code  = code;
 	info.si_addr  = addr;
-#ifdef __ARCH_SI_TRAPNO
-	info.si_trapno = trapno;
-#endif
 #ifdef __ia64__
 	info.si_imm = imm;
 	info.si_flags = flags;
@@ -3283,10 +3273,6 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 				 ((sig == SIGFPE) ||
 				  ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
 				layout = SIL_FAULT_TRAPNO;
-#ifdef __ARCH_SI_TRAPNO
-			else if (layout == SIL_FAULT)
-				layout = SIL_FAULT_TRAPNO;
-#endif
 		}
 		else if (si_code <= NSIGPOLL)
 			layout = SIL_POLL;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87bl73xx6x.fsf_-_%40disp2133.
