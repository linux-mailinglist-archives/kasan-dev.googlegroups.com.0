Return-Path: <kasan-dev+bncBCALX3WVYQORBKXVYGDQMGQEERXQLZI@googlegroups.com>
X-Original-To: lists+kasan-dev@lfdr.de
Delivered-To: lists+kasan-dev@lfdr.de
Received: from mail-yb1-xb3a.google.com (mail-yb1-xb3a.google.com [IPv6:2607:f8b0:4864:20::b3a])
	by mail.lfdr.de (Postfix) with ESMTPS id D485D3CA524
	for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 20:12:59 +0200 (CEST)
Received: by mail-yb1-xb3a.google.com with SMTP id w5-20020a0569021005b029055b51419c7dsf8805935ybt.23
        for <lists+kasan-dev@lfdr.de>; Thu, 15 Jul 2021 11:12:59 -0700 (PDT)
ARC-Seal: i=2; a=rsa-sha256; t=1626372778; cv=pass;
        d=google.com; s=arc-20160816;
        b=l6TeEZpyX26DpXLwNMaPmkWuaMDWZDsAJDZKAB95qiLWv9znS51EK2iDHlWg72xp4I
         pU+TU7ex2YAGCwnFfbP+I0qxE/KA4XbiHv1RlKu0DF6w9yaPkueMv5pOnXtCubeRvZRk
         qOBl/Y91YkyoFfWMfP4pSZuBldMTbyNDeETuo1gYn+AdgRjHErMo0o5nASBnR2azlXDx
         eV4pdhBdUTDi2Gums6XKNsf3dXek4vx8k7tsAEmHtzsbRu1JE8R3bwYSOnu3/dCWpK4u
         5oKgcD3so7FtXTMXSLcY2KjvX7Xp37LfB+ybwuZ2A93P4pD0WymWODVJEGX1P0iourOv
         LszA==
ARC-Message-Signature: i=2; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=list-unsubscribe:list-subscribe:list-archive:list-help:list-post
         :list-id:mailing-list:precedence:subject:mime-version:user-agent
         :message-id:in-reply-to:date:references:cc:to:from:sender
         :dkim-signature;
        bh=/u23nnlLIUFZTtYgH288YwPoEPk5M8lFrbFn29Fdnq8=;
        b=koLdAQFWCProytfsnuw6yiTJUDFZg3cdsGrEMIkDMxl2O71EUa7zjYcDxzMao6KCR4
         cPwObxfx9VbHkYyLXW0LB49sL3z8gee3gb/jsDeFR6txu3LMjd5fU2gKjMP+g20zECel
         cR3Rd2Rpo3pSiOOjUR5zx43oNX5gA1UWc+dP27ZHE/3eU3n12wNFUi2HPtKj9XYl7iXP
         c/1dFm4PKqIIAdAc0Q6qazOqeER+nKiFUyisKE/8cGJ4dRkAJ6MQRm+KApmwUCAEdpED
         bEvibmUtH1VSMvXj9N2np/HJru6c/p1VvCvxxeO/EXw+rauUPzXbL72/09Mmi6tPTPNk
         zXtg==
ARC-Authentication-Results: i=2; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=googlegroups.com; s=20161025;
        h=sender:from:to:cc:references:date:in-reply-to:message-id:user-agent
         :mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :list-post:list-help:list-archive:list-subscribe:list-unsubscribe;
        bh=/u23nnlLIUFZTtYgH288YwPoEPk5M8lFrbFn29Fdnq8=;
        b=ZuW+eXzp+NP0clEm7kufVJj7V7zsa7LeLQPjBBvqYNh/iYxwdJDOjXlNT/DqnQuTR2
         LuWnzhS8/qF8+NaIrskv97Cn1nji8ME9gICRPCUv7a65rZT9wJLvZbx6Dxgm7XI3cUy7
         yVTPTgtS6NzVJr6PvuGnY86tLArHq/WhCplxVFI4gwEjbc8WIJKJMr9AaO0xG2s3HqRQ
         OjrwA5WVKaLcRTJZjAq2ox1klyZI7W6GT86hYkZvReyZ+QJ0DlVeNz5xspP3zm0E6xev
         fwfwPaBfO8pAMZXxTYWTuf9eYynsHjBfM0WpLSpiryBTPSkB6TdGYlI56uq/W56JHVZI
         XHJQ==
X-Google-DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=1e100.net; s=20161025;
        h=sender:x-gm-message-state:from:to:cc:references:date:in-reply-to
         :message-id:user-agent:mime-version:subject:x-original-sender
         :x-original-authentication-results:precedence:mailing-list:list-id
         :x-spam-checked-in-group:list-post:list-help:list-archive
         :list-subscribe:list-unsubscribe;
        bh=/u23nnlLIUFZTtYgH288YwPoEPk5M8lFrbFn29Fdnq8=;
        b=KXabUguAm0kIIN4Sasua0jhUtfRUT2NPVbavrptXd1HQsbnai2IcUYy2wMnspyiCBr
         QjrLAM4wTLiHgW4Fi36LpvbIAZyHEc5WRG+KKJINsDzXNSW9QaAQ8g2orBa5MPqQ48UL
         BeoMd+Te3tNFIxduXXqjy8shi9eYAPJzt72McCbLG7MaYVdwiR0JG7V9Qzh8Y8GNfGBV
         CRtkRShtt5ZdP13b4erf+2PVcjdvroVNvXKh4ovRkJMieTtTGp2GQi+SMuRF67sRTeeh
         yxwptPYrjv156YYEJlDQq/CxaSjSQEoDE64EohkjjOuLGKybGFVIGtjPp6wnxfoFtV4H
         5wYw==
Sender: kasan-dev@googlegroups.com
X-Gm-Message-State: AOAM530WZNLrhEEk0af5aKNCq3t5+kuA+nK0LhzyfftcEFjKtmTy5t5i
	7ld08KPwxoR0zfsHrNFSWMU=
X-Google-Smtp-Source: ABdhPJyCBBl+mR39Nsso3Sl4Il91mmRR6n+hQfyk2g48Hf7tJZvYi/kGZpU4w81ybp51/xj0srN6mw==
X-Received: by 2002:a25:a369:: with SMTP id d96mr7091985ybi.463.1626372778799;
        Thu, 15 Jul 2021 11:12:58 -0700 (PDT)
X-BeenThere: kasan-dev@googlegroups.com
Received: by 2002:a25:b2a1:: with SMTP id k33ls4483138ybj.4.gmail; Thu, 15 Jul
 2021 11:12:58 -0700 (PDT)
X-Received: by 2002:a25:2a04:: with SMTP id q4mr7585138ybq.70.1626372778254;
        Thu, 15 Jul 2021 11:12:58 -0700 (PDT)
ARC-Seal: i=1; a=rsa-sha256; t=1626372778; cv=none;
        d=google.com; s=arc-20160816;
        b=VEFmENriG83KMFm2pY8CIcCeLVHJj012Jf0lnxzf5+guRqFYskiA6VRdCdx+J+RseF
         wJLhq1bFuGNicdbwmV0FMg+WCYJsn6bBbTDy/NfnVtD2Oaz+onXDJZiEh30t7uv6PzQf
         z5L0bqC1PKsfamheyF3c6GejEDe/9EqT2wObKtRhH4+Hmu0On9cCK+UkBtIMXGbrvLyi
         0f5UiFDp3ASF1Pb0fVjrdoh8GtdsHereD+GVMpDlflOIVOJA71Il4UhBl2AQZXYsdlTu
         R8y6vUeQK6n/ct5XtSQOBuHrC7EISiLIR623+NiN2eF6zij++8JUvjS+OcV8IsaMs5IT
         Jfrw==
ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=google.com; s=arc-20160816;
        h=subject:mime-version:user-agent:message-id:in-reply-to:date
         :references:cc:to:from;
        bh=LzdISlwRtgWnelz6e9/AetYZaeVZJ/yoFkrt3s0mN7k=;
        b=xvCocFb59EYdaO7ZrB2FCmKhsXCa+87kuuY+dsdY2TdhVYcSy06/rabYLutOLTE+hU
         h2BtBy/aC6ajJzVVYkvgqqFodai7s9xbbI3/ubXGhL+DC5eky+XvvonxCB5V74uCbM6G
         xcdPiwwtC2rkvHSlQzAV5ceX06XukoZDf58cTfnz+vIHLDk2p2yR+av7LnEIL6YvrxKq
         vkCv1FpjIklxyztVkFiRB6OQvyay9bP2m7eUe0iK6Hp2x+BNedb8SGISP9/DoMuTeVe4
         28daQehYXIGMAlikG/uj7PfAgF4Cjmp7BKil4mVS1WA+lEcYu55wGmNzvlyKNuoyMTOg
         fFug==
ARC-Authentication-Results: i=1; gmr-mx.google.com;
       spf=pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) smtp.mailfrom=ebiederm@xmission.com;
       dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=xmission.com
Received: from out01.mta.xmission.com (out01.mta.xmission.com. [166.70.13.231])
        by gmr-mx.google.com with ESMTPS id o187si694338ybo.0.2021.07.15.11.12.58
        for <kasan-dev@googlegroups.com>
        (version=TLS1_3 cipher=TLS_AES_256_GCM_SHA384 bits=256/256);
        Thu, 15 Jul 2021 11:12:58 -0700 (PDT)
Received-SPF: pass (google.com: domain of ebiederm@xmission.com designates 166.70.13.231 as permitted sender) client-ip=166.70.13.231;
Received: from in02.mta.xmission.com ([166.70.13.52])
	by out01.mta.xmission.com with esmtps  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45qy-00Bezt-Jx; Thu, 15 Jul 2021 12:12:56 -0600
Received: from ip68-227-160-95.om.om.cox.net ([68.227.160.95]:57090 helo=email.xmission.com)
	by in02.mta.xmission.com with esmtpsa  (TLS1.3) tls TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
	(Exim 4.93)
	(envelope-from <ebiederm@xmission.com>)
	id 1m45qv-00AozN-An; Thu, 15 Jul 2021 12:12:56 -0600
From: ebiederm@xmission.com (Eric W. Biederman)
To: Marco Elver <elver@google.com>
Cc: Arnd Bergmann <arnd@arndb.de>,  Florian Weimer <fweimer@redhat.com>,  "David S. Miller" <davem@davemloft.net>,  Peter Zijlstra <peterz@infradead.org>,  Ingo Molnar <mingo@kernel.org>,  Thomas Gleixner <tglx@linutronix.de>,  Peter Collingbourne <pcc@google.com>,  Dmitry Vyukov <dvyukov@google.com>,  Alexander Potapenko <glider@google.com>,  sparclinux <sparclinux@vger.kernel.org>,  linux-arch <linux-arch@vger.kernel.org>,  Linux Kernel Mailing List <linux-kernel@vger.kernel.org>,  Linux API <linux-api@vger.kernel.org>,  kasan-dev <kasan-dev@googlegroups.com>
References: <YIpkvGrBFGlB5vNj@elver.google.com>
	<m11rat9f85.fsf@fess.ebiederm.org>
	<CAK8P3a0+uKYwL1NhY6Hvtieghba2hKYGD6hcKx5n8=4Gtt+pHA@mail.gmail.com>
	<m15z031z0a.fsf@fess.ebiederm.org> <YIxVWkT03TqcJLY3@elver.google.com>
	<m1zgxfs7zq.fsf_-_@fess.ebiederm.org> <87a6mnzbx2.fsf_-_@disp2133>
Date: Thu, 15 Jul 2021 13:12:46 -0500
In-Reply-To: <87a6mnzbx2.fsf_-_@disp2133> (Eric W. Biederman's message of
	"Thu, 15 Jul 2021 13:09:45 -0500")
Message-ID: <87h7gvxx7l.fsf_-_@disp2133>
User-Agent: Gnus/5.13 (Gnus v5.13) Emacs/26.1 (gnu/linux)
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"
X-XM-SPF: eid=1m45qv-00AozN-An;;;mid=<87h7gvxx7l.fsf_-_@disp2133>;;;hst=in02.mta.xmission.com;;;ip=68.227.160.95;;;frm=ebiederm@xmission.com;;;spf=neutral
X-XM-AID: U2FsdGVkX1+WmhS/ukda531AwfF2+e6unIrXVWOREGA=
X-SA-Exim-Connect-IP: 68.227.160.95
X-SA-Exim-Mail-From: ebiederm@xmission.com
X-Spam-Checker-Version: SpamAssassin 3.4.2 (2018-09-13) on sa06.xmission.com
X-Spam-Level: **
X-Spam-Status: No, score=2.0 required=8.0 tests=ALL_TRUSTED,BAYES_50,
	DCC_CHECK_NEGATIVE,T_TM2_M_HEADER_IN_MSG,T_TooManySym_01,XMNoVowels,
	XMSubLong autolearn=disabled version=3.4.2
X-Spam-Report: * -1.0 ALL_TRUSTED Passed through trusted hosts only via SMTP
	*  0.8 BAYES_50 BODY: Bayes spam probability is 40 to 60%
	*      [score: 0.4991]
	*  0.7 XMSubLong Long Subject
	*  1.5 XMNoVowels Alpha-numberic number with no vowels
	*  0.0 T_TM2_M_HEADER_IN_MSG BODY: No description available.
	* -0.0 DCC_CHECK_NEGATIVE Not listed in DCC
	*      [sa06 1397; Body=1 Fuz1=1 Fuz2=1]
	*  0.0 T_TooManySym_01 4+ unique symbols in subject
X-Spam-DCC: XMission; sa06 1397; Body=1 Fuz1=1 Fuz2=1
X-Spam-Combo: **;Marco Elver <elver@google.com>
X-Spam-Relay-Country: 
X-Spam-Timing: total 2739 ms - load_scoreonly_sql: 0.04 (0.0%),
	signal_user_changed: 12 (0.4%), b_tie_ro: 10 (0.4%), parse: 1.43
	(0.1%), extract_message_metadata: 17 (0.6%), get_uri_detail_list: 5
	(0.2%), tests_pri_-1000: 15 (0.5%), tests_pri_-950: 1.37 (0.0%),
	tests_pri_-900: 1.04 (0.0%), tests_pri_-90: 2054 (75.0%), check_bayes:
	2052 (74.9%), b_tokenize: 18 (0.6%), b_tok_get_all: 10 (0.4%),
	b_comp_prob: 2.9 (0.1%), b_tok_touch_all: 2016 (73.6%), b_finish: 1.10
	(0.0%), tests_pri_0: 602 (22.0%), check_dkim_signature: 0.66 (0.0%),
	check_dkim_adsp: 3.4 (0.1%), poll_dns_idle: 1.20 (0.0%), tests_pri_10:
	3.7 (0.1%), tests_pri_500: 30 (1.1%), rewrite_mail: 0.00 (0.0%)
Subject: [PATCH 5/6] signal/alpha: si_trapno is only used with SIGFPE and SIGTRAP TRAP_UNK
X-SA-Exim-Version: 4.2.1 (built Sat, 08 Feb 2020 21:53:50 +0000)
X-SA-Exim-Scanned: Yes (on in02.mta.xmission.com)
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



While reviewing the signal handlers on alpha it became clear that
si_trapno is only set to a non-zero value when sending SIGFPE and when
sending SITGRAP with si_code TRAP_UNK.

Add send_sig_fault_trapno and send SIGTRAP TRAP_UNK, and SIGFPE with it.

Remove the define of __ARCH_SI_TRAPNO and remove the always zero
si_trapno parameter from send_sig_fault and force_sig_fault.

v1: https://lkml.kernel.org/r/m1eeers7q7.fsf_-_@fess.ebiederm.org
v2: https://lkml.kernel.org/r/20210505141101.11519-7-ebiederm@xmission.com
Signed-off-by: "Eric W. Biederman" <ebiederm@xmission.com>
---
 arch/alpha/include/uapi/asm/siginfo.h |  2 --
 arch/alpha/kernel/osf_sys.c           |  2 +-
 arch/alpha/kernel/signal.c            |  4 ++--
 arch/alpha/kernel/traps.c             | 26 +++++++++++++-------------
 arch/alpha/mm/fault.c                 |  4 ++--
 include/linux/sched/signal.h          |  2 ++
 kernel/signal.c                       | 21 +++++++++++++++++++++
 7 files changed, 41 insertions(+), 20 deletions(-)

diff --git a/arch/alpha/include/uapi/asm/siginfo.h b/arch/alpha/include/uapi/asm/siginfo.h
index 6e1a2af2f962..e08eae88182b 100644
--- a/arch/alpha/include/uapi/asm/siginfo.h
+++ b/arch/alpha/include/uapi/asm/siginfo.h
@@ -2,8 +2,6 @@
 #ifndef _ALPHA_SIGINFO_H
 #define _ALPHA_SIGINFO_H
 
-#define __ARCH_SI_TRAPNO
-
 #include <asm-generic/siginfo.h>
 
 #endif
diff --git a/arch/alpha/kernel/osf_sys.c b/arch/alpha/kernel/osf_sys.c
index d5367a1c6300..bbdb1a9a5fd8 100644
--- a/arch/alpha/kernel/osf_sys.c
+++ b/arch/alpha/kernel/osf_sys.c
@@ -876,7 +876,7 @@ SYSCALL_DEFINE5(osf_setsysinfo, unsigned long, op, void __user *, buffer,
 			if (fex & IEEE_TRAP_ENABLE_DZE) si_code = FPE_FLTDIV;
 			if (fex & IEEE_TRAP_ENABLE_INV) si_code = FPE_FLTINV;
 
-			send_sig_fault(SIGFPE, si_code,
+			send_sig_fault_trapno(SIGFPE, si_code,
 				       (void __user *)NULL,  /* FIXME */
 				       0, current);
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
index 921d4b6e4d95..e9e3de18793b 100644
--- a/arch/alpha/kernel/traps.c
+++ b/arch/alpha/kernel/traps.c
@@ -227,7 +227,7 @@ do_entArith(unsigned long summary, unsigned long write_mask,
 	}
 	die_if_kernel("Arithmetic fault", regs, 0, NULL);
 
-	send_sig_fault(SIGFPE, si_code, (void __user *) regs->pc, 0, current);
+	send_sig_fault_trapno(SIGFPE, si_code, (void __user *) regs->pc, 0, current);
 }
 
 asmlinkage void
@@ -268,13 +268,13 @@ do_entIF(unsigned long type, struct pt_regs *regs)
 			regs->pc -= 4;	/* make pc point to former bpt */
 		}
 
-		send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc, 0,
+		send_sig_fault(SIGTRAP, TRAP_BRKPT, (void __user *)regs->pc,
 			       current);
 		return;
 
 	      case 1: /* bugcheck */
-		send_sig_fault(SIGTRAP, TRAP_UNK, (void __user *) regs->pc, 0,
-			       current);
+		send_sig_fault_trapno(SIGTRAP, TRAP_UNK,
+				      (void __user *) regs->pc, 0, current);
 		return;
 		
 	      case 2: /* gentrap */
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
diff --git a/include/linux/sched/signal.h b/include/linux/sched/signal.h
index 99a9ab2b169a..6657184cef07 100644
--- a/include/linux/sched/signal.h
+++ b/include/linux/sched/signal.h
@@ -330,6 +330,8 @@ int force_sig_perf(void __user *addr, u32 type, u64 sig_data);
 
 int force_sig_ptrace_errno_trap(int errno, void __user *addr);
 int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno);
+int send_sig_fault_trapno(int sig, int code, void __user *addr, int trapno,
+			struct task_struct *t);
 
 extern int send_sig_info(int, struct kernel_siginfo *, struct task_struct *);
 extern void force_sigsegv(int sig);
diff --git a/kernel/signal.c b/kernel/signal.c
index 87a374225277..ae06a424aa72 100644
--- a/kernel/signal.c
+++ b/kernel/signal.c
@@ -1824,6 +1824,23 @@ int force_sig_fault_trapno(int sig, int code, void __user *addr, int trapno)
 	return force_sig_info(&info);
 }
 
+/* For the rare architectures that include trap information using
+ * si_trapno.
+ */
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
+
 int kill_pgrp(struct pid *pid, int sig, int priv)
 {
 	int ret;
@@ -3262,6 +3279,10 @@ enum siginfo_layout siginfo_layout(unsigned sig, int si_code)
 			else if (IS_ENABLED(CONFIG_SPARC) &&
 				 (sig == SIGILL) && (si_code == ILL_ILLTRP))
 				layout = SIL_FAULT_TRAPNO;
+			else if (IS_ENABLED(CONFIG_ALPHA) &&
+				 ((sig == SIGFPE) ||
+				  ((sig == SIGTRAP) && (si_code == TRAP_UNK))))
+				layout = SIL_FAULT_TRAPNO;
 #ifdef __ARCH_SI_TRAPNO
 			else if (layout == SIL_FAULT)
 				layout = SIL_FAULT_TRAPNO;
-- 
2.20.1

-- 
You received this message because you are subscribed to the Google Groups "kasan-dev" group.
To unsubscribe from this group and stop receiving emails from it, send an email to kasan-dev+unsubscribe@googlegroups.com.
To view this discussion on the web visit https://groups.google.com/d/msgid/kasan-dev/87h7gvxx7l.fsf_-_%40disp2133.
